//! Проверка серверов в два режима:
//!
//! - **быстрая** — только TCP-соединение до сервера (без TLS и без SNI). Безопасна
//!   для ТСПУ, поэтому идёт параллельно по всем серверам;
//! - **полная** — рукопожатие и загрузка через ядро. Каждое такое соединение
//!   проходит через NetGovernor: серверы с одним SNI проверяются по очереди,
//!   а после обнаруженной заморозки этот SNI до конца паузы не трогается.

#[cfg(test)]
mod emulator;

use crate::governor::{Decision, NetGovernor};
use crate::model::{Protocol, Server};
use crate::probe::{classify, ProbeObservation, Verdict};
use serde::Serialize;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Выполняет одну полную пробу сервера (через тестовое ядро).
pub trait Prober: Send + Sync + 'static {
    fn probe(&self, server: Server) -> impl Future<Output = ProbeObservation> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Checked {
        verdict: Verdict,
        latency_ms: Option<u64>,
    },
    /// Не проверялся: SNI заморожен или кончилось время. Повторить позже.
    Deferred { retry_after_secs: u64 },
}

/// Ключ, по которому ТСПУ считает соединения: видимый SNI, а без TLS — адрес.
pub fn sni_key(server: &Server) -> String {
    server
        .visible_sni()
        .unwrap_or(&server.address)
        .to_ascii_lowercase()
}

/// Полная проверка. `budget` ограничивает общее время: что не успели —
/// возвращается как `Deferred`. `on_result` вызывается для каждого сервера, как
/// только его результат известен (интерфейс показывает их по мере готовности).
pub async fn full_check<P: Prober>(
    servers: &[Server],
    prober: Arc<P>,
    governor: &mut NetGovernor,
    budget: Duration,
    mut on_result: impl FnMut(usize, &Outcome),
) -> Vec<Outcome> {
    let mut outcomes: Vec<Option<Outcome>> = vec![None; servers.len()];
    let mut record = |outcomes: &mut Vec<Option<Outcome>>, i: usize, o: Outcome| {
        on_result(i, &o);
        outcomes[i] = Some(o);
    };
    let deadline = Instant::now() + budget;
    let max_parallel = governor.policy().max_parallel_probes.max(1);
    let mut pending: VecDeque<usize> = (0..servers.len()).collect();
    let mut running: JoinSet<(usize, String, ProbeObservation)> = JoinSet::new();

    loop {
        let now = Instant::now().into_std();
        let mut next_wake: Option<std::time::Instant> = None;
        let mut waiting = VecDeque::new();

        // Время вышло: новые пробы не начинаем, запущенные дожидаемся.
        if Instant::now() >= deadline {
            for i in pending.drain(..) {
                record(
                    &mut outcomes,
                    i,
                    Outcome::Deferred {
                        retry_after_secs: 60,
                    },
                );
            }
        }

        while let Some(i) = pending.pop_front() {
            if running.len() >= max_parallel {
                waiting.push_back(i);
                continue;
            }
            let sni = sni_key(&servers[i]);
            match governor.try_acquire(&sni, now) {
                Decision::Allowed => {
                    let prober = Arc::clone(&prober);
                    let server = servers[i].clone();
                    running.spawn(async move { (i, sni, prober.probe(server).await) });
                }
                Decision::RetryAt(at) => {
                    next_wake = Some(next_wake.map_or(at, |w| w.min(at)));
                    waiting.push_back(i);
                }
                Decision::Frozen { until } => {
                    let retry_after_secs = until.saturating_duration_since(now).as_secs().max(1);
                    record(&mut outcomes, i, Outcome::Deferred { retry_after_secs });
                }
            }
        }
        pending = waiting;

        if running.is_empty() && pending.is_empty() {
            break;
        }

        // Просыпаемся, когда освободится лимит SNI, но не позже конца бюджета.
        let wake = next_wake.map(|w| Instant::from_std(w).min(deadline));
        tokio::select! {
            Some(joined) = running.join_next(), if !running.is_empty() => {
                if let Ok((i, sni, observation)) = joined {
                    let verdict = classify(&observation);
                    if verdict.is_freeze() {
                        governor.report_freeze(&sni, Instant::now().into_std());
                    }
                    let latency_ms = observation.latency.map(|l| l.as_millis() as u64);
                    record(&mut outcomes, i, Outcome::Checked { verdict, latency_ms });
                }
            }
            _ = tokio::time::sleep_until(wake.unwrap_or_else(Instant::now)), if wake.is_some() => {}
        }
    }

    outcomes
        .into_iter()
        .map(|o| {
            o.unwrap_or(Outcome::Deferred {
                retry_after_secs: 60,
            })
        })
        .collect()
}

/// Результат быстрой проверки одного сервера.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuickResult {
    Reachable {
        latency_ms: u64,
    },
    Unreachable,
    DnsFailed,
    /// UDP-протоколы (Hysteria2) TCP-пингом не проверить.
    NotApplicable,
}

/// Быстрая проверка: время TCP-рукопожатия до каждого сервера.
pub async fn quick_check(
    servers: &[Server],
    timeout: Duration,
    parallel: usize,
) -> Vec<QuickResult> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(parallel.max(1)));
    let mut set = JoinSet::new();
    for (i, s) in servers.iter().enumerate() {
        if matches!(s.protocol, Protocol::Hysteria2 { .. }) {
            continue;
        }
        let (host, port, sem) = (s.address.clone(), s.port, Arc::clone(&semaphore));
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            (i, tcp_ping(&host, port, timeout).await)
        });
    }
    let mut out = vec![QuickResult::NotApplicable; servers.len()];
    while let Some(Ok((i, r))) = set.join_next().await {
        out[i] = r;
    }
    out
}

// TODO(этап 3): резолвить имена серверов через выбранный DoH, а не системный DNS.
pub async fn tcp_ping(host: &str, port: u16, timeout: Duration) -> QuickResult {
    let addrs = match tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        _ => return QuickResult::DnsFailed,
    };
    let Some(addr) = addrs.first() else {
        return QuickResult::DnsFailed;
    };
    let start = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => QuickResult::Reachable {
            latency_ms: start.elapsed().as_millis() as u64,
        },
        _ => QuickResult::Unreachable,
    }
}

/// Читает поток, пока не наберётся `target` байт. Если данные перестали идти
/// дольше `stall` — это заморозка (типичный признак ТСПУ после ~16 КБ).
pub async fn measure_download<R: AsyncRead + Unpin>(
    mut reader: R,
    target: u64,
    stall: Duration,
) -> ProbeObservation {
    let mut buf = vec![0u8; 16 * 1024];
    let mut received = 0u64;
    let mut stalled = false;
    while received < target {
        match tokio::time::timeout(stall, reader.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => received += n as u64,
            Err(_) => {
                stalled = true;
                break;
            }
        }
    }
    ProbeObservation {
        dns_resolved: true,
        tcp_connected: true,
        tls_handshake_done: true,
        bytes_received: received,
        stalled,
        download_completed: received >= target,
        latency: None,
        core_error: false,
        rejected: false,
    }
}

#[cfg(test)]
mod tests {
    use super::emulator::TspuEmulator;
    use super::*;
    use crate::governor::NetPolicy;
    use crate::parser::{parse_uri, Entry};
    use tokio::io::AsyncWriteExt;

    fn servers(specs: &[(&str, &str)]) -> Vec<Server> {
        specs
            .iter()
            .map(|(ip, sni)| {
                let uri = format!(
                    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@{ip}:443?security=reality&sni={sni}&fp=firefox&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba8"
                );
                match parse_uri(&uri).unwrap() {
                    Entry::Server(s) => *s,
                    Entry::Info(_) => panic!(),
                }
            })
            .collect()
    }

    fn same_sni(n: usize) -> Vec<Server> {
        let ips: Vec<String> = (1..=n).map(|i| format!("203.0.113.{i}")).collect();
        let specs: Vec<(&str, &str)> = ips
            .iter()
            .map(|ip| (ip.as_str(), "www.microsoft.com"))
            .collect();
        servers(&specs)
    }

    fn works(o: &Outcome) -> bool {
        matches!(
            o,
            Outcome::Checked {
                verdict: Verdict::Works,
                ..
            }
        )
    }

    #[tokio::test(start_paused = true)]
    async fn emulator_catches_naive_burst() {
        // Проверка самого эмулятора: залп из 5 рукопожатий на один SNI замораживается.
        let emu = TspuEmulator::default();
        let list = same_sni(5);
        let mut set = JoinSet::new();
        let emu = Arc::new(emu);
        for s in list {
            let e = Arc::clone(&emu);
            set.spawn(async move { e.probe(s).await });
        }
        while set.join_next().await.is_some() {}
        assert!(emu.violations() > 0);
    }

    #[tokio::test(start_paused = true)]
    async fn same_sni_never_trips_tspu() {
        let emu = Arc::new(TspuEmulator::default());
        let mut gov = NetGovernor::new(NetPolicy::default());
        let list = same_sni(10);
        let started = Instant::now();
        let out = full_check(
            &list,
            Arc::clone(&emu),
            &mut gov,
            Duration::from_secs(3600),
            |_, _| {},
        )
        .await;
        assert_eq!(emu.violations(), 0);
        assert!(out.iter().all(works), "{out:?}");
        // 10 серверов по 2 в минуту — около 4,5 минут виртуального времени.
        assert!(started.elapsed() < Duration::from_secs(6 * 60));
    }

    #[tokio::test(start_paused = true)]
    async fn different_snis_run_in_parallel() {
        let emu = Arc::new(TspuEmulator::default());
        let mut gov = NetGovernor::new(NetPolicy::default());
        let list = servers(&[
            ("203.0.113.1", "a.example.com"),
            ("203.0.113.2", "b.example.com"),
            ("203.0.113.3", "c.example.com"),
            ("203.0.113.4", "d.example.com"),
        ]);
        let started = Instant::now();
        let out = full_check(&list, emu, &mut gov, Duration::from_secs(60), |_, _| {}).await;
        assert!(out.iter().all(works));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn data_freeze_stops_attempts_on_that_sni() {
        let emu = Arc::new(TspuEmulator::default().with_flagged("203.0.113.1"));
        let mut gov = NetGovernor::new(NetPolicy::default());
        let list = same_sni(5);
        let out = full_check(
            &list,
            Arc::clone(&emu),
            &mut gov,
            Duration::from_secs(3600),
            |_, _| {},
        )
        .await;
        assert!(matches!(
            out[0],
            Outcome::Checked {
                verdict: Verdict::DataFrozen,
                ..
            }
        ));
        assert!(
            out[1..]
                .iter()
                .all(|o| matches!(o, Outcome::Deferred { .. })),
            "{out:?}"
        );
        assert_eq!(emu.attempts(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn budget_defers_the_rest() {
        let emu = Arc::new(TspuEmulator::default());
        let mut gov = NetGovernor::new(NetPolicy::default());
        let out = full_check(
            &same_sni(6),
            emu,
            &mut gov,
            Duration::from_secs(30),
            |_, _| {},
        )
        .await;
        assert!(works(&out[0]) && works(&out[1]));
        assert!(
            out[2..]
                .iter()
                .all(|o| matches!(o, Outcome::Deferred { .. })),
            "{out:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn progress_reports_every_server_once() {
        let emu = Arc::new(TspuEmulator::default().with_flagged("203.0.113.1"));
        let mut gov = NetGovernor::new(NetPolicy::default());
        let mut seen = Vec::new();
        let out = full_check(
            &same_sni(4),
            emu,
            &mut gov,
            Duration::from_secs(3600),
            |i, o| seen.push((i, o.clone())),
        )
        .await;
        seen.sort_by_key(|(i, _)| *i);
        let reported: Vec<Outcome> = seen.into_iter().map(|(_, o)| o).collect();
        assert_eq!(reported, out);
    }

    #[tokio::test(start_paused = true)]
    async fn download_freeze_after_16k_is_detected() {
        let (mut server, client) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            server.write_all(&[0u8; 16 * 1024]).await.unwrap();
            // Дальше ТСПУ молча держит соединение без данных.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            drop(server);
        });
        let obs = measure_download(client, 200 * 1024, Duration::from_secs(5)).await;
        assert!(obs.stalled);
        assert_eq!(obs.bytes_received, 16 * 1024);
        assert_eq!(classify(&obs), Verdict::DataFrozen);
    }

    #[tokio::test]
    async fn download_completes() {
        let (mut server, client) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move { server.write_all(&vec![0u8; 200 * 1024]).await.unwrap() });
        let obs = measure_download(client, 200 * 1024, Duration::from_secs(5)).await;
        assert!(obs.download_completed && !obs.stalled);
    }

    #[tokio::test]
    async fn tcp_ping_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        assert!(matches!(
            tcp_ping("127.0.0.1", port, Duration::from_secs(2)).await,
            QuickResult::Reachable { .. }
        ));
    }

    #[tokio::test]
    async fn tcp_ping_closed_port() {
        // Занимаем порт и сразу освобождаем — на нём точно никто не слушает.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            tcp_ping("127.0.0.1", port, Duration::from_secs(2)).await,
            QuickResult::Unreachable
        );
    }
}
