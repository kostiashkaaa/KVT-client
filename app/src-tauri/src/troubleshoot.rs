//! «Почему не работает?» — проверка по шагам от простого к сложному: сеть, служба,
//! подписка, сервер, туннель. Итог — один понятный вывод и, если можно,
//! действие одной кнопкой.
//!
//! Сбор фактов (`gather`) отделён от выводов (`conclude`): выводы покрыты тестами.
//! Сетевых запросов немного: TCP-пинг сервера без TLS, один запрос через туннель
//! или одна проба сервера через тестовое ядро (с лимитами NetGovernor).

use crate::health::{self, Trace};
use crate::prober::CoreProber;
use crate::{display_name, query_status, watchdog, AppState};
use kvt_core::ipc::ServiceStatus;
use kvt_core::probe::{classify, Verdict};
use kvt_core::tester::{sni_key, tcp_ping, Outcome, Prober, QuickResult};
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Ok,
    Warning,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub title: &'static str,
    pub state: StepState,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fix {
    Connect,
    Disconnect,
    SwitchServer {
        key: String,
        name: String,
    },
    RefreshSubscription,
    AddSubscription,
    OpenDnsCheck,
    /// Подобрать стратегию zapret автоматически.
    ZapretAutoselect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnosis {
    pub tone: Tone,
    pub title: String,
    pub detail: String,
    pub steps: Vec<Step>,
    pub fix: Option<Fix>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubFacts {
    pub expired: bool,
    pub exhausted: bool,
}

/// Проба выбранного сервера через тестовое ядро.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeFact {
    Done(Verdict),
    /// NetGovernor не разрешил новое соединение к этому SNI.
    Postponed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub network: bool,
    /// `None` — служба не отвечает.
    pub service: Option<ServiceStatus>,
    /// `None` — подписки нет.
    pub subscription: Option<SubFacts>,
    pub server: Option<String>,
    pub server_tcp: Option<QuickResult>,
    /// Интернет без VPN (проверяется, только когда VPN отключён).
    pub internet: Option<bool>,
    pub probe: Option<ProbeFact>,
    /// Запрос через туннель (только при подключённом VPN).
    pub tunnel: Option<Result<Trace, String>>,
    /// Ключ и название рабочей замены.
    pub alternative: Option<(String, String)>,
    /// Сеть просит войти (проверяется, только если через туннель данные не идут).
    pub captive: bool,
}

struct Out {
    steps: Vec<Step>,
}

impl Out {
    fn step(&mut self, title: &'static str, state: StepState, detail: impl Into<String>) {
        self.steps.push(Step {
            title,
            state,
            detail: detail.into(),
        });
    }

    fn finish(
        self,
        tone: Tone,
        title: impl Into<String>,
        detail: impl Into<String>,
        fix: Option<Fix>,
    ) -> Diagnosis {
        Diagnosis {
            tone,
            title: title.into(),
            detail: detail.into(),
            steps: self.steps,
            fix,
        }
    }
}

fn switch(f: &Facts) -> Option<Fix> {
    f.alternative
        .clone()
        .map(|(key, name)| Fix::SwitchServer { key, name })
}

fn switch_hint(f: &Facts) -> String {
    match &f.alternative {
        Some((_, name)) => format!(" Можно переключиться на «{name}»."),
        None => " Рабочей замены в подписке не нашлось — обновите подписку или напишите в поддержку провайдера VPN.".into(),
    }
}

pub fn conclude(f: &Facts) -> Diagnosis {
    let mut out = Out { steps: Vec::new() };

    if !f.network {
        out.step("Сеть", StepState::Fail, "Нет подключения к сети");
        return out.finish(
            Tone::Error,
            "Компьютер не подключён к сети",
            "Проверьте Wi-Fi или кабель. VPN заработает, как только появится сеть.",
            None,
        );
    }
    out.step("Сеть", StepState::Ok, "Подключение к сети есть");

    let Some(service) = &f.service else {
        out.step("Служба KVT", StepState::Fail, "Служба не отвечает");
        return out.finish(
            Tone::Error,
            "Служба KVT не запущена",
            "Без службы KVT не может создать туннель. Переустановите KVT или запустите службу \
             KVTService в «Службах» Windows.",
            None,
        );
    };
    if let ServiceStatus::Failed { reason, blocked } = service {
        out.step("Служба KVT", StepState::Fail, reason.clone());
        // Текст — для службы прежней версии, которая флаг не присылает.
        let blocked = *blocked || reason.contains("Kill switch");
        return out.finish(
            Tone::Error,
            "Соединение прервалось",
            if blocked {
                "Ядро остановилось, и kill switch закрыл интернет, чтобы ничего не ушло мимо \
                 туннеля. Отключитесь, чтобы вернуть интернет, или подключитесь снова."
            } else {
                "Ядро VPN остановилось. Попробуйте подключиться снова."
            },
            Some(if blocked {
                Fix::Disconnect
            } else {
                Fix::Connect
            }),
        );
    }
    out.step("Служба KVT", StepState::Ok, "Служба работает");

    if let ServiceStatus::Zapret { strategy } = service {
        let title = kvt_core::zapret::title(strategy);
        out.step(
            "Zapret",
            StepState::Ok,
            format!("Работает, стратегия «{title}»"),
        );
        return out.finish(
            Tone::Ok,
            "Работает zapret",
            format!(
                "Обход DPI для YouTube и Discord включён (стратегия «{title}»). Если они всё равно \
                 не открываются, подберите стратегию автоматически — провайдеры блокируют по-разному."
            ),
            Some(Fix::ZapretAutoselect),
        );
    }

    let Some(sub) = &f.subscription else {
        out.step("Подписка", StepState::Fail, "Подписка не добавлена");
        return out.finish(
            Tone::Warning,
            "Нет подписки",
            "Добавьте ссылку на подписку или ключ сервера, который дал провайдер VPN.",
            Some(Fix::AddSubscription),
        );
    };
    if sub.expired || sub.exhausted {
        let what = if sub.expired {
            "Срок подписки закончился"
        } else {
            "Трафик подписки израсходован"
        };
        out.step("Подписка", StepState::Fail, what);
        return out.finish(
            Tone::Error,
            what,
            "Продлите подписку у провайдера VPN и обновите её в KVT.",
            Some(Fix::RefreshSubscription),
        );
    }
    out.step("Подписка", StepState::Ok, "Подписка действует");

    let Some(server) = &f.server else {
        out.step("Сервер", StepState::Fail, "Сервер не выбран");
        return out.finish(
            Tone::Warning,
            "Не выбран сервер",
            "Выберите сервер в списке на главной.",
            None,
        );
    };

    let connected = matches!(service, ServiceStatus::Connected { .. });
    if !connected && f.internet == Some(false) {
        out.step(
            "Интернет без VPN",
            StepState::Fail,
            "Сайты недоступны и без VPN",
        );
        return out.finish(
            Tone::Error,
            "Интернет не работает даже без VPN",
            "Сеть есть, но в интернет выйти не получается. Проблема у провайдера или роутера — \
             KVT здесь не поможет.",
            None,
        );
    }
    if !connected {
        out.step("Интернет без VPN", StepState::Ok, "Интернет работает");
    }

    match f.server_tcp {
        Some(QuickResult::DnsFailed) => {
            out.step(
                "Сервер",
                StepState::Fail,
                format!("Адрес сервера «{server}» не находится"),
            );
            return out.finish(
                Tone::Error,
                "Не удаётся найти адрес сервера",
                format!(
                    "DNS не возвращает адрес этого сервера — провайдер мог заблокировать его домен.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::OpenDnsCheck)),
            );
        }
        Some(QuickResult::Unreachable) => {
            out.step("Сервер", StepState::Fail, format!("«{server}» не отвечает"));
            return out.finish(
                Tone::Error,
                "Сервер недоступен",
                format!(
                    "Сервер не принимает соединения: он выключен или его IP заблокирован.{}",
                    switch_hint(f)
                ),
                switch(f),
            );
        }
        Some(QuickResult::Reachable { latency_ms }) => out.step(
            "Сервер",
            StepState::Ok,
            format!("«{server}» отвечает, {latency_ms} мс"),
        ),
        Some(QuickResult::NotApplicable) | None => {}
    }

    if connected && f.captive {
        out.step(
            "Сеть",
            StepState::Fail,
            "Сеть просит войти: вместо проверочного ответа пришла страница входа",
        );
        return out.finish(
            Tone::Warning,
            "Сеть просит войти",
            "Похоже на Wi-Fi гостиницы, кафе или метро: сначала нужно войти на странице сети. \
             VPN и kill switch не дают её открыть — отключите VPN, войдите и подключитесь снова.",
            Some(Fix::Disconnect),
        );
    }

    if connected {
        return match &f.tunnel {
            Some(Ok(trace)) => {
                let exit = trace
                    .country
                    .as_deref()
                    .map(|c| format!(" Выход в интернет: {c}."))
                    .unwrap_or_default();
                out.step(
                    "Туннель",
                    StepState::Ok,
                    format!("Данные идут через VPN, {} мс", trace.ms),
                );
                out.finish(
                    Tone::Ok,
                    "VPN работает",
                    format!(
                        "Трафик идёт через туннель.{exit} Если не открывается конкретный сайт, \
                         проверьте в «Маршрутизации», не идёт ли он напрямую."
                    ),
                    None,
                )
            }
            Some(Err(reason)) => {
                out.step(
                    "Туннель",
                    StepState::Fail,
                    format!("Данные не проходят ({reason})"),
                );
                out.finish(
                    Tone::Error,
                    "Подключение есть, но данные не идут",
                    format!(
                        "Туннель поднят, но сервер не пропускает трафик: провайдер режет соединение \
                         или сервер перегружен.{}",
                        switch_hint(f)
                    ),
                    switch(f),
                )
            }
            None => out.finish(Tone::Ok, "VPN подключён", "", None),
        };
    }

    match &f.probe {
        Some(ProbeFact::Done(Verdict::Works)) => {
            out.step(
                "Проверка сервера",
                StepState::Ok,
                Verdict::Works.message_ru(),
            );
            out.finish(
                Tone::Ok,
                "Сервер работает — можно подключаться",
                "Через этот сервер данные проходят. Если после подключения сайты не открываются, \
                 запустите проверку ещё раз при включённом VPN.",
                Some(Fix::Connect),
            )
        }
        Some(ProbeFact::Done(Verdict::Slow)) => {
            out.step(
                "Проверка сервера",
                StepState::Warning,
                Verdict::Slow.message_ru(),
            );
            out.finish(
                Tone::Warning,
                "Сервер работает, но медленно",
                format!(
                    "Подключиться можно, но страницы будут открываться с задержкой.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::Connect)),
            )
        }
        Some(ProbeFact::Done(verdict)) => {
            out.step("Проверка сервера", StepState::Fail, verdict.message_ru());
            let title = match verdict {
                Verdict::TlsFrozen | Verdict::DataFrozen => "Провайдер блокирует этот сервер",
                Verdict::Rejected => "Сервер отклоняет подключение",
                Verdict::ConfigError => "Сервер не поддерживается",
                Verdict::DnsFailed => "Не удаётся найти адрес сервера",
                _ => "Сервер недоступен",
            };
            out.finish(
                Tone::Error,
                title,
                format!("{}.{}", verdict.message_ru(), switch_hint(f)),
                switch(f),
            )
        }
        Some(ProbeFact::Postponed) => {
            out.step(
                "Проверка сервера",
                StepState::Warning,
                "Отложена: к этому серверу недавно подключались",
            );
            out.finish(
                Tone::Warning,
                "Повторите проверку через пару минут",
                "Частые подключения к одному серверу заметны провайдеру, поэтому KVT выдерживает \
                 паузу. Сервер отвечает — попробуйте подключиться.",
                Some(Fix::Connect),
            )
        }
        None => out.finish(
            Tone::Ok,
            "Явных проблем не найдено",
            "Попробуйте подключиться.",
            Some(Fix::Connect),
        ),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn internet_direct() -> bool {
    let timeout = Duration::from_secs(3);
    matches!(
        tcp_ping("ya.ru", 443, timeout).await,
        QuickResult::Reachable { .. }
    ) || matches!(
        tcp_ping("77.88.8.8", 53, timeout).await,
        QuickResult::Reachable { .. }
    )
}

async fn probe(state: &AppState, key: &str, server: &kvt_core::Server) -> Option<ProbeFact> {
    if state.checking.load(Ordering::SeqCst) {
        return None;
    }
    let sni = sni_key(server);
    let decision = state
        .governor
        .lock()
        .ok()?
        .try_acquire(&sni, Instant::now());
    if decision != kvt_core::governor::Decision::Allowed {
        kvt_core::netlog::record_hold(
            kvt_core::netlog::Origin::App,
            kvt_core::netlog::Purpose::ServerCheck,
            &sni,
            kvt_core::netlog::Route::TestCore,
            &decision,
        );
        return Some(ProbeFact::Postponed);
    }
    let prober = CoreProber::new().ok()?;
    let observation = prober.probe(server.clone()).await;
    let verdict = classify(&observation);
    kvt_core::tester::log_probe(&sni, verdict, &observation);
    if verdict.is_freeze() {
        if let Ok(mut g) = state.governor.lock() {
            g.report_freeze(&sni, Instant::now());
        }
    }
    if let Ok(mut outcomes) = state.outcomes.lock() {
        outcomes.insert(
            key.to_owned(),
            Outcome::Checked {
                verdict,
                latency_ms: observation.latency.map(|l| l.as_millis() as u64),
            },
        );
    }
    Some(ProbeFact::Done(verdict))
}

async fn gather(state: &AppState) -> Facts {
    let mut f = Facts {
        network: tokio::task::spawn_blocking(crate::netinfo::current)
            .await
            .ok()
            .flatten()
            .is_some(),
        ..Default::default()
    };
    if !f.network {
        return f;
    }
    f.service = query_status().await.ok().flatten();
    let selected = state.selected();
    // Срок и трафик — той подписки, из которой выбранный сервер.
    f.subscription = state.groups.lock().ok().and_then(|groups| {
        let group = match &selected {
            Some(e) => groups.iter().find(|g| g.id == e.sub)?,
            None => groups.first()?,
        };
        let m = &group.meta;
        let now = now_unix();
        Some(SubFacts {
            expired: m.expire.is_some_and(|e| e <= now),
            exhausted: matches!((m.used_bytes, m.total_bytes), (Some(u), Some(t)) if t > 0 && u >= t),
        })
    });

    let Some(entry) = selected else {
        return f;
    };
    let server = &entry.server;
    f.server = Some(display_name(server));

    let connected = matches!(f.service, Some(ServiceStatus::Connected { .. }));
    if !server.protocol.is_quic() {
        f.server_tcp = Some(tcp_ping(&server.address, server.port, Duration::from_secs(4)).await);
    }
    let server_down = matches!(
        f.server_tcp,
        Some(QuickResult::Unreachable | QuickResult::DnsFailed)
    );
    if connected {
        f.tunnel = Some(health::check(&state.health).await);
        if matches!(f.tunnel, Some(Err(_))) {
            f.captive = watchdog::captive().await == kvt_core::ipc::Captive::Portal;
        }
    } else {
        f.internet = Some(internet_direct().await);
        if f.internet == Some(true) && !server_down {
            f.probe = probe(state, &entry.key, server).await;
        }
    }

    let bad_probe = matches!(&f.probe, Some(ProbeFact::Done(v)) if *v != Verdict::Works);
    let bad_tunnel = matches!(f.tunnel, Some(Err(_)));
    if server_down || bad_probe || bad_tunnel {
        if let Some(key) = watchdog::alternatives(state, Some(&entry)).await.first() {
            f.alternative = Some((key.clone(), watchdog::server_name(state, key)));
        }
    }
    f
}

#[tauri::command]
pub async fn troubleshoot(state: State<'_, AppState>) -> Result<Diagnosis, String> {
    let diagnosis = conclude(&gather(&state).await);
    tracing::info!(title = %diagnosis.title, "«Почему не работает?»");
    if let Ok(mut last) = state.last_diagnosis.lock() {
        *last = Some(diagnosis.clone());
    }
    Ok(diagnosis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::core_select::CoreKind;

    fn base() -> Facts {
        Facts {
            network: true,
            service: Some(ServiceStatus::Disconnected),
            subscription: Some(SubFacts::default()),
            server: Some("NL".into()),
            server_tcp: Some(QuickResult::Reachable { latency_ms: 40 }),
            internet: Some(true),
            probe: Some(ProbeFact::Done(Verdict::Works)),
            tunnel: None,
            alternative: Some(("k3".into(), "DE".into())),
            captive: false,
        }
    }

    #[test]
    fn captive_portal_offers_disconnect_instead_of_another_server() {
        let mut f = base();
        f.service = Some(ServiceStatus::Connected {
            core: CoreKind::Xray,
        });
        f.probe = None;
        f.tunnel = Some(Err("нет ответа".into()));
        f.captive = true;
        let d = conclude(&f);
        assert_eq!(d.title, "Сеть просит войти");
        assert_eq!(d.fix, Some(Fix::Disconnect));
    }

    fn failing_step(d: &Diagnosis) -> Option<&'static str> {
        d.steps
            .iter()
            .find(|s| s.state == StepState::Fail)
            .map(|s| s.title)
    }

    #[test]
    fn working_server_offers_connect() {
        let d = conclude(&base());
        assert_eq!(d.tone, Tone::Ok);
        assert_eq!(d.fix, Some(Fix::Connect));
        assert_eq!(failing_step(&d), None);
    }

    #[test]
    fn first_problem_wins() {
        let mut f = base();
        f.network = false;
        f.service = None;
        let d = conclude(&f);
        assert_eq!(d.title, "Компьютер не подключён к сети");
        assert_eq!(d.steps.len(), 1);

        let mut f = base();
        f.service = None;
        assert_eq!(failing_step(&conclude(&f)), Some("Служба KVT"));
    }

    #[test]
    fn kill_switch_after_crash_offers_disconnect() {
        let mut f = base();
        f.service = Some(ServiceStatus::Failed {
            reason: "ядро остановилось".into(),
            blocked: true,
        });
        assert_eq!(conclude(&f).fix, Some(Fix::Disconnect));
    }

    #[test]
    fn expired_subscription() {
        let mut f = base();
        f.subscription = Some(SubFacts {
            expired: true,
            exhausted: false,
        });
        let d = conclude(&f);
        assert_eq!(d.fix, Some(Fix::RefreshSubscription));
        assert_eq!(d.title, "Срок подписки закончился");
    }

    #[test]
    fn no_internet_without_vpn_is_not_our_problem() {
        let mut f = base();
        f.internet = Some(false);
        let d = conclude(&f);
        assert_eq!(d.title, "Интернет не работает даже без VPN");
        assert_eq!(d.fix, None);
    }

    #[test]
    fn unreachable_server_offers_alternative() {
        let mut f = base();
        f.server_tcp = Some(QuickResult::Unreachable);
        let d = conclude(&f);
        assert_eq!(
            d.fix,
            Some(Fix::SwitchServer {
                key: "k3".into(),
                name: "DE".into()
            })
        );
        assert!(d.detail.contains("«DE»"));

        f.alternative = None;
        let d = conclude(&f);
        assert_eq!(d.fix, None);
        assert!(d.detail.contains("обновите подписку"));
    }

    #[test]
    fn dns_failure_without_alternative_opens_dns_check() {
        let mut f = base();
        f.server_tcp = Some(QuickResult::DnsFailed);
        f.alternative = None;
        assert_eq!(conclude(&f).fix, Some(Fix::OpenDnsCheck));
    }

    #[test]
    fn frozen_server() {
        let mut f = base();
        f.probe = Some(ProbeFact::Done(Verdict::DataFrozen));
        let d = conclude(&f);
        assert_eq!(d.title, "Провайдер блокирует этот сервер");
        assert!(matches!(d.fix, Some(Fix::SwitchServer { .. })));
    }

    #[test]
    fn connected_and_tunnel_works() {
        let mut f = base();
        f.service = Some(ServiceStatus::Connected {
            core: CoreKind::Xray,
        });
        f.internet = None;
        f.probe = None;
        f.tunnel = Some(Ok(Trace {
            country: Some("NL".into()),
            ms: 120,
        }));
        let d = conclude(&f);
        assert_eq!(d.tone, Tone::Ok);
        assert!(d.detail.contains("NL"));
        assert!(!d.steps.iter().any(|s| s.title == "Интернет без VPN"));
    }

    #[test]
    fn connected_but_no_data() {
        let mut f = base();
        f.service = Some(ServiceStatus::Connected {
            core: CoreKind::Xray,
        });
        f.probe = None;
        f.tunnel = Some(Err("нет ответа".into()));
        let d = conclude(&f);
        assert_eq!(d.title, "Подключение есть, но данные не идут");
        assert!(matches!(d.fix, Some(Fix::SwitchServer { key, .. }) if key == "k3"));
    }

    #[test]
    fn zapret_mode_offers_autoselect() {
        let mut f = base();
        f.service = Some(ServiceStatus::Zapret {
            strategy: "general (ALT4)".into(),
        });
        let d = conclude(&f);
        assert_eq!(d.tone, Tone::Ok);
        assert!(d.detail.contains("ALT4"));
        assert_eq!(d.fix, Some(Fix::ZapretAutoselect));
    }

    #[test]
    fn postponed_probe_does_not_alarm() {
        let mut f = base();
        f.probe = Some(ProbeFact::Postponed);
        let d = conclude(&f);
        assert_eq!(d.tone, Tone::Warning);
        assert_eq!(d.fix, Some(Fix::Connect));
    }
}
