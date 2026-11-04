//! Обработка команд. Не зависит от транспорта (pipe), поэтому покрыта тестами.

use crate::supervisor::Supervisor;
use kvt_core::ipc::{ConnectPlan, Request, Response, ServiceStatus, ZapretPlan, PROTOCOL_VERSION};

pub struct State {
    supervisor: Supervisor,
    status: ServiceStatus,
}

impl State {
    pub fn new(supervisor: Supervisor) -> Self {
        Self {
            supervisor,
            status: ServiceStatus::Disconnected,
        }
    }

    /// Актуальный статус: если ядро упало само, это видно сразу.
    fn refresh(&mut self) {
        if let Some(mut reason) = self.supervisor.exited() {
            tracing::warn!(%reason, "ядро завершилось");
            if self.supervisor.kill_switch_active() {
                reason.push_str(". Kill switch держит интернет закрытым — нажмите «Отключить» или подключитесь заново");
            }
            self.status = ServiceStatus::Failed { reason };
        }
    }

    pub async fn shutdown(&mut self) {
        self.supervisor.stop().await;
    }
}

pub async fn handle(state: &mut State, request: Request) -> Response {
    state.refresh();
    match request {
        Request::Hello { protocol_version } if protocol_version == PROTOCOL_VERSION => {
            Response::Hello {
                protocol_version: PROTOCOL_VERSION,
                service_version: env!("CARGO_PKG_VERSION").to_owned(),
            }
        }
        Request::Hello { .. } => Response::Error {
            message: "версии приложения и службы не совпадают — переустановите KVT".into(),
        },
        Request::Status => Response::Status {
            status: state.status.clone(),
        },
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
                    message: "исправление прервалось".into(),
                },
            }
        }
        Request::NetLog => Response::NetLog {
            events: kvt_core::netlog::snapshot(),
        },
        Request::Disconnect => {
            state.supervisor.stop().await;
            state.status = ServiceStatus::Disconnected;
            Response::Ok
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
    state.status = ServiceStatus::Connecting;
    match state.supervisor.start(plan).await {
        Ok(()) => {
            state.status = ServiceStatus::Connected { core: plan.core };
            Response::Status {
                status: state.status.clone(),
            }
        }
        Err(message) => {
            state.status = ServiceStatus::Failed {
                reason: message.clone(),
            };
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
/// сначала всё останавливается; переподключает приложение.
async fn maintain(state: &mut State, request: &Request) -> Response {
    state.supervisor.stop().await;
    state.status = ServiceStatus::Disconnected;
    let paths = state.supervisor.paths().clone();
    let result = match request {
        Request::ZapretUpdate => crate::zapret::update(&paths).await,
        _ => {
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
    state.status = ServiceStatus::Connecting;
    match state.supervisor.start_zapret(plan).await {
        Ok(strategy) => {
            state.status = ServiceStatus::Zapret { strategy };
            Response::Status {
                status: state.status.clone(),
            }
        }
        Err(message) => {
            state.status = ServiceStatus::Failed {
                reason: message.clone(),
            };
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
