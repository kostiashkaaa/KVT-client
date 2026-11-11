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
use kvt_core::i18n::tr;
use kvt_core::ipc::ServiceStatus;
use kvt_core::probe::{classify, Verdict};
use kvt_core::tester::{sni_key, tcp_ping, Outcome, Prober, QuickResult};
use kvt_core::trf;
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
        Some((_, name)) => trf!(
            " Можно переключиться на «{name}».",
            " You can switch to “{name}”."
        ),
        None => tr(
            " Рабочей замены в подписке не нашлось — обновите подписку или напишите в поддержку провайдера VPN.",
            " No working replacement in the subscription — update it or contact your VPN provider's support.",
        )
        .into(),
    }
}

pub fn conclude(f: &Facts) -> Diagnosis {
    let mut out = Out { steps: Vec::new() };

    if !f.network {
        out.step(
            tr("Сеть", "Network"),
            StepState::Fail,
            tr("Нет подключения к сети", "No network connection"),
        );
        return out.finish(
            Tone::Error,
            tr(
                "Компьютер не подключён к сети",
                "The computer isn't connected to a network",
            ),
            tr(
                "Проверьте Wi-Fi или кабель. VPN заработает, как только появится сеть.",
                "Check Wi-Fi or the cable. The VPN will work as soon as there's a network.",
            ),
            None,
        );
    }
    out.step(
        tr("Сеть", "Network"),
        StepState::Ok,
        tr("Подключение к сети есть", "Network connection is up"),
    );

    let Some(service) = &f.service else {
        out.step(
            tr("Служба KVT", "KVT service"),
            StepState::Fail,
            tr("Служба не отвечает", "The service doesn't respond"),
        );
        return out.finish(
            Tone::Error,
            tr("Служба KVT не запущена", "The KVT service isn't running"),
            tr(
                "Без службы KVT не может создать туннель. Переустановите KVT или запустите службу \
                 KVTService в «Службах» Windows.",
                "Without its service KVT can't create the tunnel. Reinstall KVT or start the \
                 KVTService service in Windows Services.",
            ),
            None,
        );
    };
    if let ServiceStatus::Failed { reason, blocked } = service {
        out.step(
            tr("Служба KVT", "KVT service"),
            StepState::Fail,
            reason.clone(),
        );
        // Текст — для службы прежней версии, которая флаг не присылает.
        let blocked = *blocked || reason.to_lowercase().contains("kill switch");
        return out.finish(
            Tone::Error,
            tr("Соединение прервалось", "Connection lost"),
            if blocked {
                tr(
                    "Ядро остановилось, и kill switch закрыл интернет, чтобы ничего не ушло мимо \
                     туннеля. Отключитесь, чтобы вернуть интернет, или подключитесь снова.",
                    "The core stopped, and the kill switch blocked the internet so nothing leaks \
                     outside the tunnel. Disconnect to restore the internet, or connect again.",
                )
            } else {
                tr(
                    "Ядро VPN остановилось. Попробуйте подключиться снова.",
                    "The VPN core stopped. Try connecting again.",
                )
            },
            Some(if blocked {
                Fix::Disconnect
            } else {
                Fix::Connect
            }),
        );
    }
    out.step(
        tr("Служба KVT", "KVT service"),
        StepState::Ok,
        tr("Служба работает", "The service is running"),
    );

    if let ServiceStatus::Zapret { strategy } = service {
        let title = kvt_core::zapret::title(strategy);
        out.step(
            "Zapret",
            StepState::Ok,
            trf!(
                "Работает, стратегия «{title}»",
                "Working, strategy “{title}”"
            ),
        );
        return out.finish(
            Tone::Ok,
            tr("Работает zapret", "zapret is on"),
            trf!(
                "Обход DPI для YouTube и Discord включён (стратегия «{title}»). Если они всё равно \
                 не открываются, подберите стратегию автоматически — провайдеры блокируют по-разному.",
                "DPI bypass for YouTube and Discord is on (strategy “{title}”). If they still \
                 don't open, pick a strategy automatically — ISPs block in different ways."
            ),
            Some(Fix::ZapretAutoselect),
        );
    }

    let Some(sub) = &f.subscription else {
        out.step(
            tr("Подписка", "Subscription"),
            StepState::Fail,
            tr("Подписка не добавлена", "No subscription added"),
        );
        return out.finish(
            Tone::Warning,
            tr("Нет подписки", "No subscription"),
            tr(
                "Добавьте ссылку на подписку или ключ сервера, который дал провайдер VPN.",
                "Add the subscription link or server key your VPN provider gave you.",
            ),
            Some(Fix::AddSubscription),
        );
    };
    if sub.expired || sub.exhausted {
        let what = if sub.expired {
            tr("Срок подписки закончился", "The subscription has expired")
        } else {
            tr(
                "Трафик подписки израсходован",
                "The subscription's traffic is used up",
            )
        };
        out.step(tr("Подписка", "Subscription"), StepState::Fail, what);
        return out.finish(
            Tone::Error,
            what,
            tr(
                "Продлите подписку у провайдера VPN и обновите её в KVT.",
                "Renew the subscription with your VPN provider and update it in KVT.",
            ),
            Some(Fix::RefreshSubscription),
        );
    }
    out.step(
        tr("Подписка", "Subscription"),
        StepState::Ok,
        tr("Подписка действует", "The subscription is active"),
    );

    let Some(server) = &f.server else {
        out.step(
            tr("Сервер", "Server"),
            StepState::Fail,
            tr("Сервер не выбран", "No server selected"),
        );
        return out.finish(
            Tone::Warning,
            tr("Не выбран сервер", "No server selected"),
            tr(
                "Выберите сервер в списке на главной.",
                "Pick a server from the list on the home page.",
            ),
            None,
        );
    };

    let connected = matches!(service, ServiceStatus::Connected { .. });
    if !connected && f.internet == Some(false) {
        out.step(
            tr("Интернет без VPN", "Internet without VPN"),
            StepState::Fail,
            tr(
                "Сайты недоступны и без VPN",
                "Sites are unreachable even without the VPN",
            ),
        );
        return out.finish(
            Tone::Error,
            tr("Интернет не работает даже без VPN", "The internet doesn't work even without the VPN"),
            tr(
                "Сеть есть, но в интернет выйти не получается. Проблема у провайдера или роутера — \
                 KVT здесь не поможет.",
                "There's a network, but the internet isn't reachable. The problem is with your ISP \
                 or router — KVT can't help here.",
            ),
            None,
        );
    }
    if !connected {
        out.step(
            tr("Интернет без VPN", "Internet without VPN"),
            StepState::Ok,
            tr("Интернет работает", "The internet works"),
        );
    }

    match f.server_tcp {
        Some(QuickResult::DnsFailed) => {
            out.step(
                tr("Сервер", "Server"),
                StepState::Fail,
                trf!(
                    "Адрес сервера «{server}» не находится",
                    "The address of “{server}” can't be found"
                ),
            );
            return out.finish(
                Tone::Error,
                tr("Не удаётся найти адрес сервера", "Can't find the server address"),
                trf!(
                    "DNS не возвращает адрес этого сервера — провайдер мог заблокировать его домен.{}",
                    "DNS doesn't return this server's address — your ISP may have blocked its domain.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::OpenDnsCheck)),
            );
        }
        Some(QuickResult::Unreachable) => {
            out.step(
                tr(tr("Сервер", "Server"), "Server"),
                StepState::Fail,
                trf!("«{server}» не отвечает", "“{server}” doesn't respond"),
            );
            return out.finish(
                Tone::Error,
                tr("Сервер недоступен", "Server unreachable"),
                trf!(
                    "Сервер не принимает соединения: он выключен или его IP заблокирован.{}",
                    "The server doesn't accept connections: it's off or its IP is blocked.{}",
                    switch_hint(f)
                ),
                switch(f),
            );
        }
        Some(QuickResult::Reachable { latency_ms }) => out.step(
            tr("Сервер", "Server"),
            StepState::Ok,
            trf!(
                "«{server}» отвечает, {latency_ms} мс",
                "“{server}” responds, {latency_ms} ms"
            ),
        ),
        Some(QuickResult::NotApplicable) | None => {}
    }

    if connected && f.captive {
        // Своё название шага: «Сеть» уже есть в начале списка.
        out.step(
            tr("Вход в сеть", "Network sign-in"),
            StepState::Fail,
            tr(
                "Вместо проверочного ответа пришла страница входа",
                "A sign-in page came instead of the test response",
            ),
        );
        return out.finish(
            Tone::Warning,
            tr("Сеть просит войти", "The network asks you to sign in"),
            tr(
                "Похоже на Wi-Fi гостиницы, кафе или метро: сначала нужно войти на странице сети. \
                 VPN и kill switch не дают её открыть — отключите VPN, войдите и подключитесь снова.",
                "Looks like hotel, café or metro Wi-Fi: you need to sign in on the network's page first. \
                 The VPN and kill switch keep it from opening — disconnect, sign in and connect again.",
            ),
            Some(Fix::Disconnect),
        );
    }

    if connected {
        return match &f.tunnel {
            Some(Ok(trace)) => {
                let exit = trace
                    .country
                    .as_deref()
                    .map(|c| trf!(" Выход в интернет: {c}.", " Internet exit: {c}."))
                    .unwrap_or_default();
                out.step(
                    tr("Туннель", "Tunnel"),
                    StepState::Ok,
                    trf!(
                        "Данные идут через VPN, {} мс",
                        "Data goes through the VPN, {} ms",
                        trace.ms
                    ),
                );
                out.finish(
                    Tone::Ok,
                    tr("VPN работает", "VPN works"),
                    trf!(
                        "Трафик идёт через туннель.{exit} Если не открывается конкретный сайт, \
                         проверьте в «Маршрутизации», не идёт ли он напрямую.",
                        "Traffic goes through the tunnel.{exit} If a particular site doesn't open, \
                         check in “Routing” whether it goes direct."
                    ),
                    None,
                )
            }
            Some(Err(reason)) => {
                out.step(
                    tr("Туннель", "Tunnel"),
                    StepState::Fail,
                    trf!(
                        "Данные не проходят ({reason})",
                        "No data gets through ({reason})"
                    ),
                );
                out.finish(
                    Tone::Error,
                    tr("Подключение есть, но данные не идут", "Connected, but no data is flowing"),
                    trf!(
                        "Туннель поднят, но сервер не пропускает трафик: провайдер режет соединение \
                         или сервер перегружен.{}",
                        "The tunnel is up, but the server passes no traffic: your ISP is cutting the \
                         connection or the server is overloaded.{}",
                        switch_hint(f)
                    ),
                    switch(f),
                )
            }
            None => out.finish(Tone::Ok, tr("VPN подключён", "VPN connected"), "", None),
        };
    }

    match &f.probe {
        Some(ProbeFact::Done(Verdict::Works)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Ok,
                Verdict::Works.message(),
            );
            out.finish(
                Tone::Ok,
                tr("Сервер работает — можно подключаться", "The server works — you can connect"),
                tr(
                    "Через этот сервер данные проходят. Если после подключения сайты не открываются, \
                     запустите проверку ещё раз при включённом VPN.",
                    "Data gets through this server. If sites don't open after connecting, \
                     run the check again with the VPN on.",
                ),
                Some(Fix::Connect),
            )
        }
        Some(ProbeFact::Done(Verdict::Slow)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Warning,
                Verdict::Slow.message(),
            );
            out.finish(
                Tone::Warning,
                tr(
                    "Сервер работает, но медленно",
                    "The server works, but slowly",
                ),
                trf!(
                    "Подключиться можно, но страницы будут открываться с задержкой.{}",
                    "You can connect, but pages will open with a delay.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::Connect)),
            )
        }
        Some(ProbeFact::Done(verdict)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Fail,
                verdict.message(),
            );
            let title = match verdict {
                Verdict::TlsFrozen | Verdict::DataFrozen => tr(
                    "Провайдер блокирует этот сервер",
                    "Your ISP is blocking this server",
                ),
                Verdict::Rejected => tr(
                    "Сервер отклоняет подключение",
                    "The server rejects the connection",
                ),
                Verdict::ConfigError => tr("Сервер не поддерживается", "Server not supported"),
                Verdict::DnsFailed => tr(
                    "Не удаётся найти адрес сервера",
                    "Can't find the server address",
                ),
                _ => tr("Сервер недоступен", "Server unreachable"),
            };
            out.finish(
                Tone::Error,
                title,
                format!("{}.{}", verdict.message(), switch_hint(f)),
                switch(f),
            )
        }
        Some(ProbeFact::Postponed) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Warning,
                tr(
                    "Отложена: к этому серверу недавно подключались",
                    "Postponed: this server was connected to recently",
                ),
            );
            out.finish(
                Tone::Warning,
                tr("Повторите проверку через пару минут", "Repeat the check in a couple of minutes"),
                tr(
                    "Частые подключения к одному серверу заметны провайдеру, поэтому KVT выдерживает \
                     паузу. Сервер отвечает — попробуйте подключиться.",
                    "Frequent connections to one server are noticeable to your ISP, so KVT waits. \
                     The server responds — try connecting.",
                ),
                Some(Fix::Connect),
            )
        }
        None => out.finish(
            Tone::Ok,
            tr("Явных проблем не найдено", "No obvious problems found"),
            tr("Попробуйте подключиться.", "Try connecting."),
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

/// Есть ли интернет мимо VPN. В журнале запросов — «Проверка сети», не пинг сервера.
async fn internet_direct() -> bool {
    use kvt_core::netlog::Purpose;
    use kvt_core::tester::tcp_ping_for;
    let timeout = Duration::from_secs(3);
    matches!(
        tcp_ping_for(Purpose::Captive, "ya.ru", 443, timeout).await,
        QuickResult::Reachable { .. }
    ) || matches!(
        tcp_ping_for(Purpose::Captive, "77.88.8.8", 53, timeout).await,
        QuickResult::Reachable { .. }
    )
}

async fn probe(state: &AppState, key: &str, server: &kvt_core::Server) -> Option<ProbeFact> {
    if state.checking.load(Ordering::SeqCst) {
        return None;
    }
    let sni = sni_key(server);
    let decision = state.governor.lock().ok()?.try_acquire_endpoint(
        &sni,
        Some(&server.address),
        Instant::now(),
    );
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
    // «Почему не работает?» пробует сервер, только когда VPN отключён.
    let prober = CoreProber::new(None).ok()?;
    let observation = prober.probe(server.clone()).await;
    let verdict = classify(&observation);
    kvt_core::tester::log_probe(&sni, verdict, &observation);
    if verdict.is_freeze() {
        if let Ok(mut g) = state.governor.lock() {
            g.report_freeze(&sni, Instant::now());
        }
    }
    crate::outcomes::record(
        state,
        [(
            key.to_owned(),
            Outcome::Checked {
                verdict,
                latency_ms: observation.latency.map(|l| l.as_millis() as u64),
            },
        )],
    );
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

    #[test]
    fn english_texts() {
        use kvt_core::i18n::{with, Lang};
        let d = with(Lang::En, || {
            conclude(&Facts {
                network: false,
                ..base()
            })
        });
        assert_eq!(d.title, "The computer isn't connected to a network");
        assert_eq!(d.steps[0].title, "Network");
        let d = with(Lang::En, || {
            conclude(&Facts {
                server_tcp: Some(QuickResult::Unreachable),
                ..base()
            })
        });
        assert!(d.detail.contains("You can switch to “DE”"), "{}", d.detail);
    }

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
        assert_eq!(failing_step(&d), Some("Вход в сеть"));
        let mut titles: Vec<_> = d.steps.iter().map(|s| s.title).collect();
        titles.dedup();
        assert_eq!(titles.len(), d.steps.len(), "названия шагов повторяются");
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
