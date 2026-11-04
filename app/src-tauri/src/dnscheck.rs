//! Проверка DNS из текущей сети (выводы — `kvt_core::dns::analyze`).
//!
//! Объём запросов небольшой и фиксированный: около 30 DNS-запросов по несколько
//! десятков байт и по одному TLS-соединению на каждый DoT- и DoH-резолвер (запросы
//! DoH к одному резолверу идут по одному соединению HTTP/2). Повторный запуск в
//! течение минуты отдаёт прошлый результат.

use crate::{query_status, AppState};
use kvt_core::dns::{
    self, wire, Observations, QueryResult, Resolver, Source, Via, RESOLVERS, SPOOF_DOMAINS, WHOAMI,
};
use kvt_core::ipc::ServiceStatus;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::State;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const UDP_TIMEOUT: Duration = Duration::from_millis(2500);
const TLS_TIMEOUT: Duration = Duration::from_secs(5);
const REUSE_FOR: Duration = Duration::from_secs(60);

fn random_id() -> u16 {
    let mut h = RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    h.finish() as u16
}

fn failed(e: impl std::fmt::Display) -> QueryResult {
    QueryResult::Failed(e.to_string())
}

async fn udp(server: Ipv4Addr, name: &str) -> QueryResult {
    udp_to(SocketAddr::from((server, 53)), name).await
}

/// Запись в журнал запросов: один DNS-запрос к резолверу.
fn log_query(host: &str, via: &str, result: &QueryResult) {
    use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
    let (outcome, ms, detail) = match result {
        QueryResult::Answer { ms, .. } => (Outcome::Ok, Some(*ms), via.to_owned()),
        QueryResult::Timeout => (Outcome::Failed, None, format!("{via}: нет ответа")),
        QueryResult::Failed(e) => (Outcome::Failed, None, format!("{via}: {e}")),
    };
    let mut event =
        netlog::Event::new(Origin::App, Purpose::Dns, host, Route::Direct, outcome).detail(detail);
    if let Some(ms) = ms {
        event = event.ms(Duration::from_millis(ms));
    }
    netlog::record(event);
}

async fn udp_to(server: SocketAddr, name: &str) -> QueryResult {
    let result = udp_query(server, name).await;
    log_query(&server.to_string(), "UDP", &result);
    result
}

async fn udp_query(server: SocketAddr, name: &str) -> QueryResult {
    let id = random_id();
    let Ok(q) = wire::query(id, name, wire::TYPE_A) else {
        return failed("некорректное имя");
    };
    let attempt = async {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await.map_err(failed)?;
        socket.connect(server).await.map_err(failed)?;
        let start = Instant::now();
        socket.send(&q).await.map_err(failed)?;
        let mut buf = [0u8; 1500];
        // Ответ с чужим id пропускаем: так подмену с опозданием не примем за ответ.
        loop {
            let n = socket.recv(&mut buf).await.map_err(failed)?;
            if let Ok(answer) = wire::parse(&buf[..n], id) {
                return Ok(QueryResult::Answer {
                    answer,
                    ms: start.elapsed().as_millis() as u64,
                });
            }
        }
    };
    match tokio::time::timeout(UDP_TIMEOUT, attempt).await {
        Ok(Ok(r) | Err(r)) => r,
        Err(_) => QueryResult::Timeout,
    }
}

async fn dot(endpoint: dns::Endpoint, name: &str) -> QueryResult {
    let result = dot_query(endpoint, name).await;
    log_query(endpoint.host, "DoT", &result);
    result
}

async fn dot_query(endpoint: dns::Endpoint, name: &str) -> QueryResult {
    let id = random_id();
    let Ok(q) = wire::query(id, name, wire::TYPE_A) else {
        return failed("некорректное имя");
    };
    let attempt = async {
        let start = Instant::now();
        let tcp = TcpStream::connect((endpoint.ip, 853))
            .await
            .map_err(|_| QueryResult::Timeout)?;
        let connector = native_tls::TlsConnector::new().map_err(failed)?;
        let mut tls = tokio_native_tls::TlsConnector::from(connector)
            .connect(endpoint.host, tcp)
            .await
            .map_err(failed)?;
        let mut frame = (q.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&q);
        tls.write_all(&frame).await.map_err(failed)?;
        let len = tls.read_u16().await.map_err(failed)?;
        let mut body = vec![0u8; usize::from(len)];
        tls.read_exact(&mut body).await.map_err(failed)?;
        let answer = wire::parse(&body, id).map_err(failed)?;
        Ok(QueryResult::Answer {
            answer,
            ms: start.elapsed().as_millis() as u64,
        })
    };
    match tokio::time::timeout(TLS_TIMEOUT, attempt).await {
        Ok(Ok(r) | Err(r)) => r,
        Err(_) => QueryResult::Timeout,
    }
}

/// Клиент DoH: имена резолверов привязаны к их IP — системный DNS (который может
/// быть подменён) для этого не нужен. Системный прокси не используется.
fn doh_client() -> reqwest::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .timeout(TLS_TIMEOUT)
        .connect_timeout(TLS_TIMEOUT);
    for doh in RESOLVERS.iter().filter_map(|r| r.doh) {
        b = b.resolve(doh.host, SocketAddr::from((doh.ip, 443)));
    }
    b.build()
}

async fn doh(client: &reqwest::Client, endpoint: dns::Endpoint, name: &str) -> QueryResult {
    let result = doh_query(client, endpoint, name).await;
    log_query(endpoint.host, "DoH", &result);
    result
}

async fn doh_query(client: &reqwest::Client, endpoint: dns::Endpoint, name: &str) -> QueryResult {
    let id = 0; // RFC 8484: в DoH id = 0, ответ привязан к HTTP-запросу.
    let Ok(q) = wire::query(id, name, wire::TYPE_A) else {
        return failed("некорректное имя");
    };
    let start = Instant::now();
    let response = client
        .post(format!("https://{}/dns-query", endpoint.host))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(q)
        .send()
        .await;
    let response = match response {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => return failed(format!("HTTP {}", r.status().as_u16())),
        Err(e) if e.is_timeout() || e.is_connect() => return QueryResult::Timeout,
        Err(e) => return failed(e),
    };
    match response.bytes().await {
        Ok(body) => match wire::parse(&body, id) {
            Ok(answer) => QueryResult::Answer {
                answer,
                ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => failed(e),
        },
        Err(_) => QueryResult::Timeout,
    }
}

async fn ask(client: &reqwest::Client, r: &Resolver, via: Via, name: &str) -> QueryResult {
    match via {
        Via::Udp => udp(r.udp, name).await,
        Via::Dot => dot(r.dot, name).await,
        Via::Doh => match r.doh {
            Some(endpoint) => doh(client, endpoint, name).await,
            None => failed("не поддерживается"),
        },
    }
}

pub async fn collect(system_server: Option<Ipv4Addr>) -> Observations {
    let client = match doh_client() {
        Ok(c) => Arc::new(c),
        Err(_) => return Observations::default(),
    };
    let mut set = tokio::task::JoinSet::new();
    for r in RESOLVERS {
        for via in [Via::Udp, Via::Dot, Via::Doh] {
            // Способ не поддерживается — не спрашиваем: в отчёте будет «не проверялся».
            if via != Via::Udp && r.endpoint(via).is_none() {
                continue;
            }
            let client = Arc::clone(&client);
            set.spawn(async move {
                let result = ask(&client, r, via, WHOAMI).await;
                (None, Source::Resolver(r.id, via), result)
            });
        }
    }
    // Подмену проверяем там, где она возможна: DNS сети и UDP к публичным резолверам.
    // Эталон — DoH Cloudflare и Google.
    for domain in SPOOF_DOMAINS {
        if let Some(server) = system_server {
            set.spawn(async move { (Some(domain), Source::System, udp(server, domain).await) });
        }
        for r in RESOLVERS {
            set.spawn(async move {
                (
                    Some(domain),
                    Source::Resolver(r.id, Via::Udp),
                    udp(r.udp, domain).await,
                )
            });
        }
        for id in ["cloudflare", "google"] {
            let Some((r, endpoint)) = dns::resolver(id).and_then(|r| Some((r, r.doh?))) else {
                continue;
            };
            let client = Arc::clone(&client);
            set.spawn(async move {
                let result = doh(&client, endpoint, domain).await;
                (Some(domain), Source::Resolver(r.id, Via::Doh), result)
            });
        }
    }

    let system_whoami = match system_server {
        Some(server) => Some(udp(server, WHOAMI).await),
        None => None,
    };
    let mut obs = Observations {
        system_server,
        system_whoami,
        ..Default::default()
    };
    while let Some(Ok((domain, source, result))) = set.join_next().await {
        match (domain, source) {
            (Some(domain), source) => obs.spoof.push((domain, source, result)),
            (None, Source::Resolver(id, via)) => obs.whoami.push((id, via, result)),
            (None, Source::System) => {}
        }
    }
    obs
}

/// Проверка DNS. При подключённом VPN запросы ушли бы в туннель и проверили бы
/// не ту сеть, поэтому она идёт только при отключённом.
#[tauri::command]
pub async fn dns_check(state: State<'_, AppState>) -> Result<dns::DnsReport, String> {
    if matches!(
        query_status().await,
        Ok(Some(ServiceStatus::Connected { .. }))
    ) {
        return Err("Отключите VPN: проверка DNS смотрит на сеть провайдера напрямую.".into());
    }
    if let Some((at, report)) = state
        .dns_report
        .lock()
        .map_err(crate::errors::state)?
        .clone()
    {
        if at.elapsed() < REUSE_FOR {
            return Ok(report);
        }
    }
    let system_server = tokio::task::spawn_blocking(crate::netinfo::current)
        .await
        .ok()
        .flatten()
        .and_then(|n| n.dns.first().copied());
    let report = dns::analyze(&collect(system_server).await);
    *state.dns_report.lock().map_err(crate::errors::state)? =
        Some((Instant::now(), report.clone()));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_ignores_foreign_answers() {
        // Локальный «резолвер» сначала шлёт ответ с чужим id, потом настоящий.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80;
            reply[7] = 1;
            reply.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 0, 0, 2]);
            let mut fake = reply.clone();
            fake[..2].copy_from_slice(&id.wrapping_add(1).to_be_bytes());
            fake[reply.len() - 1] = 66;
            server.send_to(&fake, peer).await.unwrap();
            server.send_to(&reply, peer).await.unwrap();
        });
        let QueryResult::Answer { answer, .. } = udp_to(addr, "example.com").await else {
            panic!("ожидался ответ");
        };
        assert_eq!(answer.a, [Ipv4Addr::new(10, 0, 0, 2)]);
    }

    #[tokio::test]
    async fn silent_server_is_timeout() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        assert_eq!(udp_to(addr, "example.com").await, QueryResult::Timeout);
        drop(server);
    }

    /// Проверка из этой сети: `cargo test -p kvt-app real_dns -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "отправляет DNS-запросы в интернет"]
    async fn real_dns_check() {
        let server = crate::netinfo::current().and_then(|n| n.dns.first().copied());
        let report = dns::analyze(&collect(server).await);
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
}
