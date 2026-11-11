//! Обработка команд. Не зависит от транспорта (pipe), поэтому покрыта тестами.

use crate::session::Session;
use crate::supervisor::Supervisor;
use kvt_core::ipc::{ConnectPlan, Request, Response, ServiceStatus, ZapretPlan, PROTOCOL_VERSION};

pub struct State {
    supervisor: Supervisor,
    status: ServiceStatus,
    /// Время и трафик с «Подключить»; `None` — ничего не запущено.
    session: Option<Session>,
}

impl State {
    pub fn new(supervisor: Supervisor) -> Self {
        Self {
            supervisor,
            status: ServiceStatus::Disconnected,
            session: None,
        }
    }

    /// Актуальный статус: если ядро упало само или в его журнале сработало
    /// правило ошибок, это видно сразу.
    async fn refresh(&mut self) {
        let reason = match self.supervisor.exited() {
            Some(reason) => Some(reason),
            None => self.supervisor.handle_issue().await,
        };
        if let Some(mut reason) = reason {
            if self.supervisor.kill_switch_active() {
                reason.push_str(" Kill switch держит интернет закрытым — нажмите «Отключить» или подключитесь заново.");
            }
            self.status = ServiceStatus::Failed {
                reason,
                blocked: self.supervisor.kill_switch_active(),
            };
            self.session = None;
        }
    }

    /// Работает VPN или zapret (или идёт переподключение) — сеанс продолжается.
    fn active(&self) -> bool {
        matches!(
            self.status,
            ServiceStatus::Connected { .. }
                | ServiceStatus::Zapret { .. }
                | ServiceStatus::Connecting
        )
    }

    /// Перед запуском: при работающем сеансе — дочитать счётчики прежнего
    /// адаптера (сейчас ядро его удалит), иначе начать новый сеанс.
    fn begin(&mut self) {
        let active = self.active();
        match self.session.as_mut() {
            Some(session) if active => session.sample(),
            _ => self.session = Some(Session::new()),
        }
    }

    pub fn status_response(&mut self) -> Response {
        let active = self.active();
        let session = match self.session.as_mut() {
            Some(session) if active => {
                session.sample();
                Some(session.info())
            }
            _ => None,
        };
        Response::Status {
            status: self.status.clone(),
            session,
        }
    }

    pub async fn shutdown(&mut self) {
        self.supervisor.stop().await;
    }
}

/// Ответ на Hello: сверка версии протокола, состояние не нужно.
pub fn hello(request: &Request) -> Response {
    match request {
        Request::Hello { protocol_version } if *protocol_version == PROTOCOL_VERSION => {
            Response::Hello {
                protocol_version: PROTOCOL_VERSION,
                service_version: env!("CARGO_PKG_VERSION").to_owned(),
            }
        }
        _ => Response::Error {
            message: "Окно KVT и служба разных версий. Переустановите KVT — они обновятся вместе."
                .into(),
        },
    }
}

pub async fn handle(state: &mut State, request: Request) -> Response {
    if matches!(request, Request::Hello { .. }) {
        return hello(&request);
    }
    state.refresh().await;
    match request {
        request @ Request::Hello { .. } => hello(&request),
        Request::Status => state.status_response(),
        Request::Connect(plan) => connect(state, &plan).await,
        Request::StartZapret(plan) => start_zapret(state, &plan).await,
        Request::ZapretStrategies => Response::Strategies {
            strategies: crate::zapret::strategies(state.supervisor.paths()),
        },
        Request::ZapretConflicts => Response::Conflicts {
            conflicts: crate::zapret::conflicts(
                state.supervisor.paths(),
                state.supervisor.zapret_pid(),
            )
            .into_iter()
            .map(|(c, _)| c)
            .collect(),
        },
        Request::ZapretInfo => {
            Response::ZapretInfo(Box::new(crate::zapret::info(state.supervisor.paths())))
        }
        Request::ZapretUpdate | Request::ZapretRepair => maintain(state, &request).await,
        Request::StopConflicts => Response::Conflicts {
            conflicts: crate::zapret::stop_conflicts(
                state.supervisor.paths(),
                state.supervisor.zapret_pid(),
            ),
        },
        Request::AuditFix(fix) => {
            // PowerShell и sc.exe работают секунды — не держим поток обработки.
            match tokio::task::spawn_blocking(move || crate::audit::fix(&fix)).await {
                Ok(Ok(())) => Response::Ok,
                Ok(Err(message)) => Response::Error { message },
                Err(_) => Response::Error {
                    message:
                        "Исправление прервалось. Повторите; если не выйдет — сохраните диагностику."
                            .into(),
                },
            }
        }
        Request::NetLog => Response::NetLog {
            events: kvt_core::netlog::snapshot(),
        },
        Request::ServiceLog => Response::ServiceLog {
            log: crate::logging::tail(),
            core: kvt_core::redact::text(&state.supervisor.recent_log(200).join("\n")),
        },
        Request::CaptiveCheck => Response::Captive {
            state: crate::net::captive_check().await,
        },
        Request::Ping { targets } => crate::net::ping(targets).await,
        Request::Disconnect => {
            state.supervisor.stop().await;
            state.status = ServiceStatus::Disconnected;
            state.session = None;
            Response::Ok
        }
    }
}

/// Команда, которую можно прервать: `Connect` и `StartZapret` качают списки и ждут
/// адаптер десятки секунд, и «Отключить» не должно ждать их конца. Когда `cancel`
/// завершается, недоделанный запуск бросается (дочерние процессы закрываются вместе
/// с ним — `kill_on_drop` и job object), а всё запущенное останавливается.
pub async fn handle_or_cancel(
    state: &mut State,
    request: Request,
    cancel: impl std::future::Future<Output = ()>,
) -> Response {
    let done = tokio::select! {
        // Отмена — первой: «Отключить», пришедшее раньше, не даёт начать запуск.
        biased;
        () = cancel => None,
        response = handle(state, request) => Some(response),
    };
    match done {
        Some(response) => response,
        None => {
            tracing::info!("подключение отменено");
            state.supervisor.stop().await;
            state.status = ServiceStatus::Disconnected;
            state.session = None;
            Response::Error {
                message: kvt_core::ipc::CANCELLED.into(),
            }
        }
    }
}

async fn connect(state: &mut State, plan: &ConnectPlan) -> Response {
    // Служба не доверяет приложению: план проверяется повторно.
    if let Err(e) = plan.routing.validate() {
        return Response::Error {
            message: e.to_string(),
        };
    }
    if let Err(e) = plan.dns.validate() {
        return Response::Error {
            message: e.to_string(),
        };
    }
    if let Some(message) = plan.zapret.as_ref().and_then(invalid_zapret) {
        return Response::Error { message };
    }
    state.begin();
    state.status = ServiceStatus::Connecting;
    match state.supervisor.start(plan).await {
        Ok(()) => {
            state.status = ServiceStatus::Connected { core: plan.core };
            state.status_response()
        }
        Err(message) => {
            tracing::warn!(%message, "подключение не удалось");
            state.status = ServiceStatus::Failed {
                reason: message.clone(),
                blocked: state.supervisor.kill_switch_active(),
            };
            state.session = None;
            Response::Error { message }
        }
    }
}

/// Проверка до запуска чего-либо: имя стратегии и домены — без путей и спецсимволов.
fn invalid_zapret(plan: &ZapretPlan) -> Option<String> {
    if !kvt_core::zapret::valid_id(&plan.strategy) {
        return Some(format!("неизвестная стратегия «{}»", plan.strategy));
    }
    plan.domains
        .iter()
        .chain(&plan.exclude_domains)
        .find(|d| !kvt_core::zapret::valid_domain(d))
        .map(|d| format!("недопустимый домен «{d}»"))
}

/// Обновление и переустановка трогают файлы, которыми пользуется winws, поэтому
/// перед установкой всё останавливается; переподключает приложение. Обновление
/// скачивается заранее, пока VPN работает: GitHub бывает доступен только через туннель.
async fn maintain(state: &mut State, request: &Request) -> Response {
    let paths = state.supervisor.paths().clone();
    let prepared = match request {
        Request::ZapretUpdate => {
            let http = match crate::net::NetClient::new(kvt_core::netlog::Purpose::Update) {
                Ok(h) if state.supervisor.vpn_running() => h.with_tunnel_fallback(),
                Ok(h) => h,
                Err(e) => {
                    return Response::Error {
                        message: e.to_string(),
                    }
                }
            };
            match crate::zapret::fetch_update(&paths, &http).await {
                // Обновлять нечего — подключение не трогаем.
                Ok(Err(report)) => return Response::Maintenance(Box::new(report)),
                Ok(Ok(prepared)) => Some(prepared),
                Err(message) => return Response::Error { message },
            }
        }
        _ => None,
    };
    state.supervisor.stop().await;
    state.status = ServiceStatus::Disconnected;
    state.session = None;
    let result = match prepared {
        Some(prepared) => crate::zapret::install_update(&paths, prepared),
        None => {
            // Драйвер общий: пока им пользуется чужой winws, его не трогаем.
            let foreign = crate::zapret::conflicts(&paths, None)
                .iter()
                .any(|(c, _)| !c.service);
            crate::zapret::repair(&paths, !foreign).await
        }
    };
    match result {
        Ok(report) => Response::Maintenance(Box::new(report)),
        Err(message) => Response::Error { message },
    }
}

async fn start_zapret(state: &mut State, plan: &ZapretPlan) -> Response {
    if let Some(message) = invalid_zapret(plan) {
        return Response::Error { message };
    }
    state.begin();
    state.status = ServiceStatus::Connecting;
    match state.supervisor.start_zapret(plan).await {
        Ok(strategy) => {
            state.status = ServiceStatus::Zapret { strategy };
            state.status_response()
        }
        Err(message) => {
            state.status = ServiceStatus::Failed {
                reason: message.clone(),
                blocked: state.supervisor.kill_switch_active(),
            };
            state.session = None;
            Response::Error { message }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::Paths;
    use kvt_core::core_select::CoreKind;
    use kvt_core::parser::{parse_uri, Entry};
    use kvt_core::routing::{Action, Layer, Matcher, RoutingPlan, Rule};

    fn state() -> State {
        let tmp = std::env::temp_dir().join("kvt-handler-test");
        State::new(Supervisor::new(Paths {
            cores: tmp.clone(),
            rules: tmp.clone(),
            run: tmp.clone(),
            zapret: tmp.clone(),
            zapret_lists: tmp.clone(),
            zapret_update: tmp,
        }))
    }

    #[tokio::test]
    async fn version_mismatch_is_reported() {
        let mut st = state();
        let resp = handle(
            &mut st,
            Request::Hello {
                protocol_version: PROTOCOL_VERSION + 1,
            },
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[tokio::test]
    async fn invalid_routing_is_rejected_before_anything_runs() {
        let Entry::Server(server) = parse_uri("trojan://p@vpn.example.com:443").expect("ссылка")
        else {
            panic!("ожидался сервер")
        };
        let mut routing = RoutingPlan::new(Action::Proxy);
        routing.push(Rule {
            layer: Layer::Provider,
            matcher: Matcher::DomainSuffix("x.com".into()),
            action: Action::Zapret,
        });
        let plan = ConnectPlan {
            core: CoreKind::Xray,
            server: *server,
            routing,
            kill_switch: true,
            dns: Default::default(),
            zapret: None,
        };
        let mut st = state();
        let Response::Error { message } =
            handle(&mut st, Request::Connect(Box::new(plan.clone()))).await
        else {
            panic!("ожидалась ошибка")
        };
        assert!(message.contains("zapret"));
        assert_eq!(st.status, ServiceStatus::Disconnected);

        // DNS-адрес не из каталога — тоже отказ до запуска чего-либо.
        let mut plan = plan;
        plan.routing = RoutingPlan::new(Action::Proxy);
        plan.dns.local = "127.0.0.1:5353".into();
        let Response::Error { message } = handle(&mut st, Request::Connect(Box::new(plan))).await
        else {
            panic!("ожидалась ошибка")
        };
        assert!(message.contains("DNS"));
        assert_eq!(st.status, ServiceStatus::Disconnected);
    }

    #[tokio::test]
    async fn cancelled_start_leaves_service_disconnected() {
        let mut st = state();
        let plan = ZapretPlan {
            strategy: "general".into(),
            game_filter: Default::default(),
            tcp_timestamps: false,
            domains: vec![],
            exclude_domains: vec![],
            ipset: false,
        };
        // «Отключить» уже пришло: запуск не начинается вовсе.
        let resp = handle_or_cancel(&mut st, Request::StartZapret(Box::new(plan)), async {}).await;
        assert_eq!(
            resp,
            Response::Error {
                message: kvt_core::ipc::CANCELLED.into()
            }
        );
        assert_eq!(st.status, ServiceStatus::Disconnected);
        assert!(st.session.is_none());

        // Без отмены команда отвечает как обычно.
        let resp = handle_or_cancel(&mut st, Request::Status, std::future::pending()).await;
        assert!(matches!(resp, Response::Status { .. }));
    }

    #[tokio::test]
    async fn zapret_strategy_path_is_rejected() {
        let mut st = state();
        for strategy in [r"..\..\evil", "general\"; calc", ""] {
            let plan = ZapretPlan {
                strategy: strategy.into(),
                game_filter: Default::default(),
                tcp_timestamps: false,
                domains: vec![],
                exclude_domains: vec![],
                ipset: false,
            };
            let resp = handle(&mut st, Request::StartZapret(Box::new(plan))).await;
            assert!(matches!(resp, Response::Error { .. }), "{strategy}");
        }
        let plan = ZapretPlan {
            strategy: "general".into(),
            game_filter: Default::default(),
            tcp_timestamps: false,
            domains: vec!["x.com\n--debug=@C:\\evil".into()],
            exclude_domains: vec![],
            ipset: false,
        };
        let Response::Error { message } =
            handle(&mut st, Request::StartZapret(Box::new(plan))).await
        else {
            panic!("ожидалась ошибка")
        };
        assert!(message.contains("домен"));
        assert_eq!(st.status, ServiceStatus::Disconnected);
    }
}
