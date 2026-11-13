//! Проверка серверов в два режима:
//!
//! - **быстрая** — только TCP-соединение до сервера (без TLS и без SNI). Безопасна
//!   для ТСПУ, поэтому идёт параллельно по всем серверам;
//! - **полная** — рукопожатие и загрузка через ядро. Каждое такое соединение
//!   проходит через NetGovernor: серверы с одним SNI проверяются по очереди,
//!   а после обнаруженной заморозки этот SNI до конца паузы не трогается.

#[cfg(test)]
mod emulator;

pub use crate::dns::names::Doh;
use crate::dns::names::{self, Lookup};
use crate::governor::{Decision, NetGovernor};
use crate::model::Server;
use crate::netlog::{self, Origin, Purpose, Route};
use crate::probe::{classify, ProbeObservation, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
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
///
/// `governor` — общий для всего приложения и блокируется только на каждое решение:
/// проверка идёт минутами, а подписки, «Почему не работает?» и автопереключение всё
/// это время должны видеть те же лимиты и заморозки.
pub async fn full_check<P: Prober>(
    servers: &[Server],
    prober: Arc<P>,
    governor: &Mutex<NetGovernor>,
    budget: Duration,
    mut on_result: impl FnMut(usize, &Outcome),
) -> Vec<Outcome> {
    let mut outcomes: Vec<Option<Outcome>> = vec![None; servers.len()];
    let mut record = |outcomes: &mut Vec<Option<Outcome>>, i: usize, o: Outcome| {
        on_result(i, &o);
        outcomes[i] = Some(o);
    };
    let deadline = Instant::now() + budget;
    let max_parallel = lock(governor).policy().max_parallel_probes.max(1);
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
            let decision =
                lock(governor).try_acquire_endpoint(&sni, Some(&servers[i].address), now);
            match decision {
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
                    netlog::record(
                        netlog::Event::new(
                            Origin::App,
                            Purpose::ServerCheck,
                            &sni,
                            Route::TestCore,
                            netlog::Outcome::Frozen,
                        )
                        .detail(format!("повтор через {retry_after_secs} с")),
                    );
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
                    log_probe(&sni, verdict, &observation);
                    if verdict.is_freeze() {
                        lock(governor).report_freeze(&sni, Instant::now().into_std());
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

/// Состояние NetGovernor переживает панику в другом потоке: лимиты и заморозки
/// важнее, чем согласованность одной записи.
fn lock(governor: &Mutex<NetGovernor>) -> std::sync::MutexGuard<'_, NetGovernor> {
    governor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Запись полной проверки сервера в журнал запросов.
pub fn log_probe(sni: &str, verdict: Verdict, observation: &ProbeObservation) {
    let outcome = if matches!(verdict, Verdict::Works | Verdict::Slow) {
        netlog::Outcome::Ok
    } else {
        netlog::Outcome::Failed
    };
    let mut event = netlog::Event::new(
        Origin::App,
        Purpose::ServerCheck,
        sni,
        Route::TestCore,
        outcome,
    )
    .detail(verdict.message());
    if let Some(latency) = observation.latency {
        event = event.ms(latency);
    }
    netlog::record(event);
}

/// Результат быстрой проверки одного сервера.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    doh: &Doh<'_>,
    timeout: Duration,
    parallel: usize,
) -> Vec<QuickResult> {
    let targets: Vec<Option<(String, u16)>> = servers
        .iter()
        .map(|s| {
            // UDP-протоколы (Hysteria2) TCP-пингом не проверить.
            (!s.protocol.is_quic()).then(|| (s.address.clone(), s.port))
        })
        .collect();
    ping_all(&targets, doh, None, Origin::App, timeout, parallel).await
}

/// TCP-пинг списка серверов (`None` — не проверять). Имена — через DoH
/// ([`names`]), не системным DNS. `local` — адрес источника: сокет, привязанный к
/// адресу физического адаптера, идёт мимо TUN (так служба пингует, когда VPN
/// подключён, — иначе соединение принял бы сам TUN за 0 мс).
pub async fn ping_all(
    targets: &[Option<(String, u16)>],
    doh: &Doh<'_>,
    local: Option<Ipv4Addr>,
    origin: Origin,
    timeout: Duration,
    parallel: usize,
) -> Vec<QuickResult> {
    let hosts: Vec<String> = targets.iter().flatten().map(|(h, _)| h.clone()).collect();
    let found = names::resolve(&hosts, doh, local, origin).await;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(parallel.max(1)));
    let mut set = JoinSet::new();
    for (i, t) in targets.iter().enumerate() {
        let Some((host, port)) = t.clone() else {
            continue;
        };
        let lookup = found.get(&host).cloned().unwrap_or(Lookup::Failed);
        let sem = Arc::clone(&semaphore);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let target = format!("{host}:{port}");
            let result = ping_logged(
                &target,
                lookup,
                port,
                local,
                origin,
                Purpose::ServerPing,
                timeout,
            )
            .await;
            (i, result)
        });
    }
    let mut out = vec![QuickResult::NotApplicable; targets.len()];
    while let Some(Ok((i, r))) = set.join_next().await {
        out[i] = r;
    }
    out
}

/// TCP-пинг одного сервера из окна (VPN не подключён), имя — через DoH.
pub async fn tcp_ping(host: &str, port: u16, doh: &Doh<'_>, timeout: Duration) -> QuickResult {
    let target = [Some((host.to_owned(), port))];
    ping_all(&target, doh, None, Origin::App, timeout, 1)
        .await
        .pop()
        .unwrap_or(QuickResult::DnsFailed)
}

/// TCP-пинг не VPN-сервера (например, «есть ли интернет»): в журнале — с этой целью.
/// Здесь системный DNS — то, что проверяется: работает ли сеть как есть.
pub async fn tcp_ping_for(
    purpose: Purpose,
    host: &str,
    port: u16,
    timeout: Duration,
) -> QuickResult {
    let lookup = match tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => Lookup::Found(addrs.map(|a| a.ip()).collect()),
        _ => Lookup::Failed,
    };
    let target = format!("{host}:{port}");
    ping_logged(&target, lookup, port, None, Origin::App, purpose, timeout).await
}

async fn ping_logged(
    target: &str,
    lookup: Lookup,
    port: u16,
    local: Option<Ipv4Addr>,
    origin: Origin,
    purpose: Purpose,
    timeout: Duration,
) -> QuickResult {
    let failure = match &lookup {
        Lookup::NotFound => Some(crate::i18n::tr("адрес не найден", "address not found")),
        Lookup::Failed => Some(crate::i18n::tr(
            "не удалось узнать адрес",
            "couldn't look up the address",
        )),
        Lookup::Found(_) => None,
    };
    let result = match lookup {
        Lookup::Found(ips) => tcp_ping_inner(&ips, port, local, timeout).await,
        _ => QuickResult::DnsFailed,
    };
    let event = |outcome| netlog::Event::new(origin, purpose, target, Route::Direct, outcome);
    netlog::record(match &result {
        QuickResult::Reachable { latency_ms } => {
            event(netlog::Outcome::Ok).ms(Duration::from_millis(*latency_ms))
        }
        QuickResult::Unreachable => event(netlog::Outcome::Failed)
            .detail(crate::i18n::tr("TCP не открылся", "TCP didn't open")),
        QuickResult::DnsFailed => event(netlog::Outcome::Failed)
            .detail(failure.unwrap_or(crate::i18n::tr("адрес не найден", "address not found"))),
        QuickResult::NotApplicable => return result,
    });
    result
}

async fn tcp_ping_inner(
    ips: &[IpAddr],
    port: u16,
    local: Option<Ipv4Addr>,
    timeout: Duration,
) -> QuickResult {
    // С адресом источника IPv4 годится только IPv4-адрес сервера.
    let ip = match local {
        Some(_) => ips.iter().find(|a| a.is_ipv4()),
        None => ips.first(),
    };
    let Some(&ip) = ip else {
        return QuickResult::DnsFailed;
    };
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    let connect = async {
        match local {
            Some(src) => {
                let socket = tokio::net::TcpSocket::new_v4()?;
                socket.bind(SocketAddr::from((src, 0)))?;
                socket.connect(addr).await
            }
            None => tokio::net::TcpStream::connect(addr).await,
        }
    };
    match tokio::time::timeout(timeout, connect).await {
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

    /// Прежний строгий режим: лимит на весь SNI, без учёта адреса сервера.
    fn strict() -> NetPolicy {
        NetPolicy {
            per_endpoint: false,
            ..NetPolicy::default()
        }
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
        let gov = Mutex::new(NetGovernor::new(strict()));
        let list = same_sni(10);
        let started = Instant::now();
        let out = full_check(
            &list,
            Arc::clone(&emu),
            &gov,
            Duration::from_secs(3600),
            |_, _| {},
        )
        .await;
        assert_eq!(emu.violations(), 0);
        assert!(out.iter().all(works), "{out:?}");
        // 10 серверов по 2 в минуту — около 4,5 минут виртуального времени.
        assert!(started.elapsed() < Duration::from_secs(6 * 60));
    }

    /// Лимит на пару SNI и адрес: если ТСПУ тоже считает по паре, десять серверов
    /// под один SNI проверяются за секунды без единой заморозки.
    #[tokio::test(start_paused = true)]
    async fn per_endpoint_is_fast_when_tspu_counts_per_endpoint() {
        let emu = Arc::new(TspuEmulator::default().per_endpoint());
        let gov = Mutex::new(NetGovernor::new(NetPolicy {
            per_endpoint: true,
            ..NetPolicy::default()
        }));
        let started = Instant::now();
        let out = full_check(
            &same_sni(10),
            Arc::clone(&emu),
            &gov,
            Duration::from_secs(3600),
            |_, _| {},
        )
        .await;
        assert_eq!(emu.violations(), 0);
        assert!(out.iter().all(works), "{out:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    /// Худший случай: ТСПУ считает на весь SNI. Тогда лимит на пару вызывает одну
    /// заморозку; пока её итог не пришёл, в замороженный SNI успевают уйти пробы,
    /// идущие параллельно (до `max_parallel_probes`), — дальше SNI не трогается до
    /// конца паузы, остальное откладывается. Цена, на которую пошли ради скорости
    /// (`per_endpoint` включён по умолчанию с 2026-11-12).
    #[tokio::test(start_paused = true)]
    async fn per_endpoint_damage_is_one_freeze_when_tspu_counts_per_sni() {
        let emu = Arc::new(TspuEmulator::default());
        let gov = Mutex::new(NetGovernor::new(NetPolicy {
            per_endpoint: true,
            ..NetPolicy::default()
        }));
        let out = full_check(
            &same_sni(10),
            Arc::clone(&emu),
            &gov,
            Duration::from_secs(60),
            |_, _| {},
        )
        .await;
        assert_eq!(emu.violations(), 1);
        assert!(gov
            .lock()
            .unwrap()
            .frozen_until("www.microsoft.com", std::time::Instant::now())
            .is_some());
        let count = |f: fn(&Outcome) -> bool| out.iter().filter(|o| f(o)).count();
        let frozen = count(|o| {
            matches!(
                o,
                Outcome::Checked {
                    verdict: Verdict::TlsFrozen,
                    ..
                }
            )
        });
        let parallel = NetPolicy::default().max_parallel_probes;
        assert!((1..=parallel).contains(&frozen), "{out:?}");
        assert_eq!(count(works), 3, "{out:?}");
        assert_eq!(
            count(|o| matches!(o, Outcome::Deferred { .. })),
            10 - 3 - frozen
        );
    }

    #[tokio::test(start_paused = true)]
    async fn different_snis_run_in_parallel() {
        let emu = Arc::new(TspuEmulator::default());
        let gov = Mutex::new(NetGovernor::new(NetPolicy::default()));
        let list = servers(&[
            ("203.0.113.1", "a.example.com"),
            ("203.0.113.2", "b.example.com"),
            ("203.0.113.3", "c.example.com"),
            ("203.0.113.4", "d.example.com"),
        ]);
        let started = Instant::now();
        let out = full_check(&list, emu, &gov, Duration::from_secs(60), |_, _| {}).await;
        assert!(out.iter().all(works));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn data_freeze_stops_attempts_on_that_sni() {
        let emu = Arc::new(TspuEmulator::default().with_flagged("203.0.113.1"));
        let gov = Mutex::new(NetGovernor::new(strict()));
        let list = same_sni(5);
        let out = full_check(
            &list,
            Arc::clone(&emu),
            &gov,
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
        let gov = Mutex::new(NetGovernor::new(strict()));
        let out = full_check(&same_sni(6), emu, &gov, Duration::from_secs(30), |_, _| {}).await;
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
        let gov = Mutex::new(NetGovernor::new(strict()));
        let mut seen = Vec::new();
        let out = full_check(
            &same_sni(4),
            emu,
            &gov,
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

    /// Тестам сеть не нужна: IP в адресе резолвер не спрашивает.
    fn no_net_governor() -> Mutex<NetGovernor> {
        Mutex::new(NetGovernor::new(NetPolicy::default()))
    }

    fn doh(governor: &Mutex<NetGovernor>) -> Doh<'_> {
        Doh {
            first: "cloudflare",
            governor,
        }
    }

    #[tokio::test]
    async fn tcp_ping_local_listener() {
        let governor = no_net_governor();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        assert!(matches!(
            tcp_ping("127.0.0.1", port, &doh(&governor), Duration::from_secs(2)).await,
            QuickResult::Reachable { .. }
        ));
    }

    /// Так пингует служба при подключённом VPN: сокет привязан к адресу источника.
    #[tokio::test]
    async fn ping_all_from_local_address() {
        let governor = no_net_governor();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let out = ping_all(
            &[Some(("127.0.0.1".into(), port)), None],
            &doh(&governor),
            Some(Ipv4Addr::LOCALHOST),
            Origin::Service,
            Duration::from_secs(2),
            4,
        )
        .await;
        assert!(matches!(out[0], QuickResult::Reachable { .. }), "{out:?}");
        assert_eq!(out[1], QuickResult::NotApplicable);
    }

    #[tokio::test]
    async fn tcp_ping_closed_port() {
        let governor = no_net_governor();
        // Занимаем порт и сразу освобождаем — на нём точно никто не слушает.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            tcp_ping("127.0.0.1", port, &doh(&governor), Duration::from_secs(2)).await,
            QuickResult::Unreachable
        );
    }

    /// Имя, которое и спрашивать нечего, — «адрес не найден» без сети.
    #[tokio::test]
    async fn tcp_ping_bad_name_is_dns_failed() {
        let governor = no_net_governor();
        assert_eq!(
            tcp_ping("a..b", 443, &doh(&governor), Duration::from_secs(2)).await,
            QuickResult::DnsFailed
        );
    }
}
