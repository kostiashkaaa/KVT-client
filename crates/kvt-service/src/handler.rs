//! Обработка команд. Не зависит от транспорта (pipe), поэтому покрыта тестами.

use crate::session::Session;
use crate::supervisor::{Shared, Supervisor};
use kvt_core::ipc::{ConnectPlan, Request, Response, ServiceStatus, ZapretPlan, PROTOCOL_VERSION};

pub struct State {
    supervisor: Supervisor,
    status: ServiceStatus,
    /// Время и трафик с «Подключить»; `None` — ничего не запущено.
    session: Option<Session>,
}

impl State {
    pub fn new(supervisor: Supervisor) -> Self {
        // Kill switch восстановлен после сбоя службы (`restore_kill_switch`). Причину
        // пишет `status_response`: язык окна служба узнаёт только из Hello.
        let status = if supervisor.kill_switch_active() {
            ServiceStatus::Failed {
                reason: String::new(),
                blocked: true,
            }
        } else {
            ServiceStatus::Disconnected
        };
        Self {
            supervisor,
            status,
            session: None,
        }
    }

    /// Актуальный статус: если ядро упало само или в его журнале сработало
    /// правило ошибок, это видно сразу. Переподключение по ошибке (`reconnect`)
    /// идёт секунды — его делает только `reconnect_or_cancel`.
    async fn refresh(&mut self, reconnect: bool) {
        let reason = match self.supervisor.exited() {
            Some(reason) => Some(reason),
            None => self.supervisor.handle_issue(reconnect).await,
        };
        if let Some(mut reason) = reason {
            if self.supervisor.kill_switch_active() {
                reason.push_str(kvt_core::i18n::tr(
                    " Kill switch держит интернет закрытым — нажмите «Отключить» или подключитесь заново.",
                    " The kill switch is keeping the internet blocked — press “Disconnect” or connect again.",
                ));
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
        let mut status = self.status.clone();
        if let ServiceStatus::Failed {
            reason,
            blocked: true,
        } = &mut status
        {
            if reason.is_empty() {
                *reason = kvt_core::i18n::tr(
                    "Служба KVT перезапустилась после сбоя. Kill switch держит интернет закрытым — подключитесь заново или нажмите «Отключить».",
                    "The KVT service restarted after a failure. The kill switch is keeping the internet blocked — connect again or press “Disconnect”.",
                )
                .into();
            }
        }
        Response::Status { status, session }
    }

    pub async fn shutdown(&mut self) {
        self.supervisor.stop().await;
    }

    pub fn shared(&self) -> Shared {
        self.supervisor.shared()
    }

    /// Ядро сообщило об ошибке, после которой положено переподключиться.
    pub fn reconnect_pending(&self) -> bool {
        self.supervisor.reconnect_pending()
    }

    /// Всё остановлено по «Отключить», прервавшему запуск или переподключение.
    async fn abort(&mut self) {
        tracing::info!("подключение отменено");
        self.supervisor.stop().await;
        self.status = ServiceStatus::Disconnected;
        self.session = None;
    }
}

/// Ответ на Hello: сверка версии протокола, состояние не нужно.
pub fn hello(request: &Request) -> Response {
    match request {
        Request::Hello {
            protocol_version,
            lang,
        } if *protocol_version == PROTOCOL_VERSION => {
            // Тексты для окна — на его языке. Клиент у службы один (kvt.exe).
            kvt_core::i18n::set(*lang);
            Response::Hello {
                protocol_version: PROTOCOL_VERSION,
                service_version: env!("CARGO_PKG_VERSION").to_owned(),
            }
        }
        _ => Response::Error {
            message: kvt_core::i18n::tr(
                "Окно KVT и служба разных версий. Переустановите KVT — они обновятся вместе.",
                "The KVT window and service are different versions. Reinstall KVT so they update together.",
            )
            .into(),
        },
    }
}

/// Команды, которым не нужно состояние подключения: служба отвечает на них сразу, не
/// дожидаясь блокировки, которую держит «Подключить» (качает списки, ждёт адаптер)
/// или установка обновления zapret. Иначе журнал, меню трея, проверка страницы входа
/// и экспорт диагностики висели бы всё это время. `Err` — команде нужно состояние.
pub async fn stateless(shared: &Shared, request: Request) -> Result<Response, Request> {
    let response = match request {
        request @ Request::Hello { .. } => hello(&request),
        Request::Ping { targets } => crate::net::ping(targets).await,
        Request::NetLog => Response::NetLog {
            events: kvt_core::netlog::snapshot(),
        },
        Request::ServiceLog => Response::ServiceLog {
            log: crate::logging::tail(),
            core: kvt_core::redact::text(&shared.recent_log(200).join("\n")),
        },
        Request::CaptiveCheck => Response::Captive {
            state: crate::net::captive_check().await,
        },
        Request::ZapretStrategies => Response::Strategies {
            strategies: crate::zapret::strategies(shared.paths()),
        },
        Request::ZapretInfo => Response::ZapretInfo(Box::new(crate::zapret::info(shared.paths()))),
        Request::ZapretConflicts => {
            // tasklist работает секунды — не держим поток обработки.
            let shared = shared.clone();
            let found = tokio::task::spawn_blocking(move || {
                crate::zapret::conflicts(shared.paths(), shared.zapret_pid())
            })
            .await
            .unwrap_or_default();
            Response::Conflicts {
                conflicts: found.into_iter().map(|(c, _)| c).collect(),
            }
        }
        Request::AuditFix(fix) => {
            // PowerShell и sc.exe работают секунды — не держим поток обработки.
            match tokio::task::spawn_blocking(move || crate::audit::fix(&fix)).await {
                Ok(Ok(())) => Response::Ok,
                Ok(Err(message)) => Response::Error { message },
                Err(_) => Response::Error {
                    message: kvt_core::i18n::tr(
                        "Исправление прервалось. Повторите; если не выйдет — сохраните диагностику.",
                        "The fix was interrupted. Try again; if it fails, save diagnostics.",
                    )
                    .into(),
                },
            }
        }
        request => return Err(request),
    };
    Ok(response)
}

pub async fn handle(state: &mut State, request: Request) -> Response {
    let request = match stateless(&state.shared(), request).await {
        Ok(response) => return response,
        Err(request) => request,
    };
    match request {
        Request::Status => {
            state.refresh(false).await;
            state.status_response()
        }
        Request::Connect(plan) => connect(state, &plan).await,
        Request::StartZapret(plan) => start_zapret(state, &plan).await,
        Request::ZapretUpdate => {
            let vpn = state.supervisor.vpn_running();
            match fetch_zapret_update(&state.shared(), vpn).await {
                Ok(prepared) => install_zapret(state, Some(prepared)).await,
                Err(response) => response,
            }
        }
        Request::ZapretRepair => install_zapret(state, None).await,
        Request::StopConflicts => {
            // tasklist и пауза после остановки — не на потоке обработки.
            let paths = state.supervisor.paths().clone();
            let own = state.supervisor.zapret_pid();
            Response::Conflicts {
                conflicts: tokio::task::spawn_blocking(move || {
                    crate::zapret::stop_conflicts(&paths, own)
                })
                .await
                .unwrap_or_default(),
            }
        }
        Request::Disconnect => {
            state.supervisor.stop().await;
            state.status = ServiceStatus::Disconnected;
            state.session = None;
            Response::Ok
        }
        // Остальное обслуживает `stateless`.
        _ => Response::Error {
            message: kvt_core::i18n::tr("неизвестная команда", "unknown command").into(),
        },
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
            state.abort().await;
            Response::Error {
                message: kvt_core::ipc::cancelled().into(),
            }
        }
    }
}

/// Переподключение по ошибке ядра (`State::reconnect_pending`). Идёт отдельно от
/// команд окна и прерывается «Отключить», как обычный запуск.
pub async fn reconnect_or_cancel(state: &mut State, cancel: impl std::future::Future<Output = ()>) {
    let done = tokio::select! {
        biased;
        () = cancel => false,
        () = state.refresh(true) => true,
    };
    if !done {
        state.abort().await;
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
    // Конфиг ядра служба соберёт из этих полей и запустит от SYSTEM: `extra` XHTTP
    // мог бы задать пути к файлам (`masterKeyLog`), адрес — что угодно.
    if let Err(e) = kvt_core::parser::check_server(&plan.server) {
        return Response::Error {
            message: kvt_core::compile::CompileError::from(e).to_string(),
        };
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
        return Some(kvt_core::trf!(
            "неизвестная стратегия «{}»",
            "unknown strategy “{}”",
            plan.strategy
        ));
    }
    plan.domains
        .iter()
        .chain(&plan.exclude_domains)
        .find(|d| !kvt_core::zapret::valid_domain(d))
        .map(|d| kvt_core::trf!("недопустимый домен «{d}»", "invalid domain “{d}”"))
}

/// «Обновить zapret», шаг 1 — без блокировки состояния: узнать последний релиз и
/// скачать архив (до нескольких минут), пока VPN и winws работают: GitHub бывает
/// доступен только через туннель. `Err` — ответ окну: обновлять нечего или ошибка.
pub async fn fetch_zapret_update(
    shared: &Shared,
    vpn_running: bool,
) -> Result<crate::zapret::Prepared, Response> {
    let http = match crate::net::NetClient::new(kvt_core::netlog::Purpose::Update) {
        Ok(h) if vpn_running => h.with_tunnel_fallback(),
        Ok(h) => h,
        Err(e) => {
            return Err(Response::Error {
                message: e.to_string(),
            })
        }
    };
    match crate::zapret::fetch_update(shared.paths(), &http).await {
        // Обновлять нечего — подключение не трогаем.
        Ok(Err(report)) => Err(Response::Maintenance(Box::new(report))),
        Ok(Ok(prepared)) => Ok(prepared),
        Err(message) => Err(Response::Error { message }),
    }
}

/// Шаг 2 обновления (`prepared`) или переустановка (`None`). Они трогают файлы,
/// которыми пользуется winws, поэтому сначала всё останавливается; переподключает
/// приложение.
pub async fn install_zapret(
    state: &mut State,
    prepared: Option<crate::zapret::Prepared>,
) -> Response {
    let paths = state.supervisor.paths().clone();
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

    /// Без восстановленного kill switch служба стартует отключённой; восстановленный
    /// (`restore_kill_switch`) виден окну как «интернет закрыт» с причиной.
    #[test]
    fn restored_kill_switch_status_has_reason() {
        let mut st = state();
        assert!(matches!(st.status, ServiceStatus::Disconnected));
        st.status = ServiceStatus::Failed {
            reason: String::new(),
            blocked: true,
        };
        let Response::Status {
            status: ServiceStatus::Failed { reason, blocked },
            ..
        } = st.status_response()
        else {
            panic!("ожидался статус Failed");
        };
        assert!(blocked);
        assert!(reason.contains("Kill switch"), "{reason}");
    }

    /// Журналы и сведения — без состояния (служба отвечает, не дожидаясь подключения);
    /// запуск, остановка и обслуживание zapret — только под блокировкой.
    #[tokio::test]
    async fn stateless_requests_do_not_need_state() {
        let shared = state().shared();
        assert!(matches!(
            stateless(&shared, Request::NetLog).await,
            Ok(Response::NetLog { .. })
        ));
        assert!(matches!(
            stateless(&shared, Request::ServiceLog).await,
            Ok(Response::ServiceLog { .. })
        ));
        for request in [
            Request::Status,
            Request::Disconnect,
            Request::StopConflicts,
            Request::ZapretUpdate,
            Request::ZapretRepair,
        ] {
            assert!(stateless(&shared, request).await.is_err());
        }
    }

    /// «Отключить» во время переподключения по ошибке: всё остановлено.
    #[tokio::test]
    async fn cancelled_reconnect_disconnects() {
        let mut st = state();
        st.status = ServiceStatus::Connected {
            core: kvt_core::core_select::CoreKind::Xray,
        };
        reconnect_or_cancel(&mut st, std::future::ready(())).await;
        assert!(matches!(st.status, ServiceStatus::Disconnected));
    }

    #[tokio::test]
    async fn version_mismatch_is_reported() {
        let mut st = state();
        let resp = handle(
            &mut st,
            Request::Hello {
                protocol_version: PROTOCOL_VERSION + 1,
                lang: kvt_core::i18n::Lang::Ru,
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

    /// Окну служба не доверяет: сервер, который парсер не пропустил бы, отвергается
    /// до запуска чего-либо.
    #[tokio::test]
    async fn forged_server_is_rejected_before_anything_runs() {
        let Entry::Server(server) = parse_uri("trojan://p@vpn.example.com:443").expect("ссылка")
        else {
            panic!("ожидался сервер")
        };
        let mut server = *server;
        server.address = "vpn.example.com\n\"evil".into();
        let plan = ConnectPlan {
            core: CoreKind::Xray,
            server,
            routing: RoutingPlan::new(Action::Proxy),
            kill_switch: false,
            dns: Default::default(),
            zapret: None,
        };
        let mut st = state();
        let resp = handle(&mut st, Request::Connect(Box::new(plan))).await;
        assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
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
                message: kvt_core::ipc::cancelled().into()
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
