//! Сбор фактов: статус службы, подписка, TCP-пинг сервера, проба через тестовое ядро или
//! туннель (с лимитами NetGovernor).

use super::{Facts, ProbeFact, ServiceFact, SubFacts};
use crate::health::{self};
use crate::prober::CoreProber;
use crate::{display_name, query_status, watchdog, AppState};
use kvt_core::ipc::ServiceStatus;
use kvt_core::probe::{classify, Verdict};
use kvt_core::services::{Health, Via};
use kvt_core::tester::{sni_key, Outcome, Prober, QuickResult};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    let prober = CoreProber::new(state, None).ok()?;
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

/// `focus` — сервис, из-за которого запустили проверку: попадает в факты как есть, а
/// замена серверу ищется и тогда, когда плох сервис за туннелем.
pub(super) async fn gather(state: &AppState, focus: Option<ServiceFact>) -> Facts {
    let mut f = Facts {
        network: tokio::task::spawn_blocking(crate::netinfo::current)
            .await
            .ok()
            .flatten()
            .is_some(),
        focus,
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
    if !server.protocol.is_udp_only() {
        // При подключённом VPN пингует служба мимо туннеля: соединение окна принял
        // бы сам TUN за 0 мс, и мёртвый сервер выглядел бы рабочим.
        let first = state.doh_first();
        let doh = kvt_core::tester::Doh {
            first: &first,
            governor: &state.governor,
        };
        f.server_tcp = crate::ping_servers(&doh, std::slice::from_ref(server))
            .await
            .ok()
            .and_then(|mut results| results.pop());
    }
    let server_down = matches!(
        f.server_tcp,
        Some(QuickResult::Unreachable | QuickResult::DnsFailed)
    );
    if connected {
        f.tunnel = Some(
            health::check(&state.health)
                .await
                .map_err(|e| e.to_string()),
        );
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
    // Сервис за туннелем или прокси не открывается: другой сервер подписки может помочь.
    let bad_service = f
        .focus
        .as_ref()
        .is_some_and(|s| s.health != Health::Works && matches!(s.via, Via::Vpn | Via::Proxy));
    if server_down || bad_probe || bad_tunnel || bad_service {
        if let Some(key) = watchdog::alternatives(state, Some(&entry)).await.first() {
            f.alternative = Some((key.clone(), watchdog::server_name(state, key)));
        }
    }
    f
}
