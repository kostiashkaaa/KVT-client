//! Проверка утечек. Почти всё — локально, без запросов в интернет:
//!
//! - **открытые прокси**: слушающие порты на этом компьютере, которые отвечают
//!   на SOCKS5 без пароля. Через такой порт любая программа узнает IP VPN-сервера
//!   (уязвимость, найденная runetfreedom в 2026 году);
//! - **маршруты IPv4/IPv6**: какой исходный адрес выбирает система для выхода в
//!   интернет (UDP «connect» не отправляет пакетов);
//! - **DNS**: один запрос `whoami.akamai.net` показывает, чей резолвер на самом деле
//!   отвечает на запросы системы (запрос пишется в `netlog`).

use kvt_core::dns::{self, in_nets, RESOLVERS, WHOAMI};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::process::CommandExt as _;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenProxy {
    pub port: u16,
    pub process: Option<String>,
    /// Порт из списка, по которому ищут прокси методички «выявления VPN».
    pub known_scan_port: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Check {
    Ok { detail: String },
    Warning { detail: String },
    Info { detail: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakReport {
    /// Проверка шла при подключённом VPN: иначе маршруты и DNS только для сведения.
    pub connected: bool,
    pub open_proxies: Vec<OpenProxy>,
    pub ipv4_route: Check,
    pub ipv6_route: Check,
    pub dns: Check,
}

/// `remote` — id резолвера DoH в туннеле из настроек.
pub async fn run(connected: bool, remote: &str) -> LeakReport {
    let (open_proxies, ipv4_route, ipv6_route, dns) = tokio::join!(
        open_proxies(),
        ipv4_route(connected),
        ipv6_route(connected),
        dns(connected, remote)
    );
    LeakReport {
        connected,
        open_proxies,
        ipv4_route,
        ipv6_route,
        dns,
    }
}

/// Порты из методички по выявлению VPN (по публикациям 2026 года).
fn is_known_scan_port(port: u16) -> bool {
    matches!(port, 1080 | 9000 | 5555 | 16000..=16100)
}

/// Порты, которые слушают на loopback или на всех интерфейсах, и PID владельца.
fn listening_ports(netstat: &str) -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    for line in netstat.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let [proto, local, foreign, .., pid] = cols.as_slice() else {
            continue;
        };
        if !proto.eq_ignore_ascii_case("TCP") {
            continue;
        }
        // Слушающий сокет — у него нет удалённого адреса (независимо от языка Windows).
        if *foreign != "0.0.0.0:0" && *foreign != "[::]:0" {
            continue;
        }
        let Ok(addr) = local.parse::<SocketAddr>() else {
            continue;
        };
        let reachable_locally = addr.ip().is_loopback() || addr.ip().is_unspecified();
        if let (true, Ok(pid)) = (reachable_locally, pid.parse::<u32>()) {
            if !out.iter().any(|(p, _)| *p == addr.port()) {
                out.push((addr.port(), pid));
            }
        }
    }
    out
}

fn command_output(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// PID → имя процесса по `tasklist /FO CSV /NH`.
fn process_names() -> HashMap<u32, String> {
    command_output("tasklist", &["/FO", "CSV", "/NH"])
        .lines()
        .filter_map(|line| {
            let mut fields = line.split("\",\"").map(|f| f.trim_matches('"'));
            let name = fields.next()?.to_owned();
            let pid = fields.next()?.parse().ok()?;
            Some((pid, name))
        })
        .collect()
}

/// SOCKS5-приветствие «без аутентификации». Ответ `05 00` — прокси открыт для всех.
async fn is_open_socks5(port: u16) -> bool {
    let attempt = async {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).await.ok()?;
        Some(reply == [0x05, 0x00])
    };
    matches!(
        tokio::time::timeout(Duration::from_millis(700), attempt).await,
        Ok(Some(true))
    )
}

async fn open_proxies() -> Vec<OpenProxy> {
    let ports = tokio::task::spawn_blocking(|| {
        let netstat = command_output("netstat", &["-ano", "-p", "TCP"])
            + &command_output("netstat", &["-ano", "-p", "TCPv6"]);
        listening_ports(&netstat)
    })
    .await
    .unwrap_or_default();
    let names = tokio::task::spawn_blocking(process_names)
        .await
        .unwrap_or_default();

    let mut set = tokio::task::JoinSet::new();
    // Системные порты (< 1024) прокси не используют.
    for (port, pid) in ports.into_iter().filter(|(p, _)| *p >= 1024) {
        set.spawn(async move { (port, pid, is_open_socks5(port).await) });
    }
    let mut found = Vec::new();
    while let Some(Ok((port, pid, open))) = set.join_next().await {
        if open {
            found.push(OpenProxy {
                port,
                process: names.get(&pid).cloned(),
                known_scan_port: is_known_scan_port(port),
            });
        }
    }
    found.sort_by_key(|p| p.port);
    found
}

/// Исходный адрес, который система выберет для выхода к `target`. Пакеты не отправляются.
async fn source_address(bind: &str, target: SocketAddr) -> Option<IpAddr> {
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(target).await.ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// Адреса интерфейса TUN (см. compile: 172.19.0.1/30 и fdfe:dcba:9876::1/126).
fn is_tun_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..3] == [172, 19, 0],
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfdfe, 0xdcba, 0x9876],
    }
}

async fn ipv4_route(connected: bool) -> Check {
    let Some(src) = source_address("0.0.0.0:0", SocketAddr::from(([1, 1, 1, 1], 53))).await else {
        return Check::Info {
            detail: "Нет маршрута IPv4 в интернет".into(),
        };
    };
    match (connected, is_tun_address(src)) {
        (true, true) => Check::Ok {
            detail: "Трафик IPv4 идёт через туннель".into(),
        },
        (true, false) => Check::Warning {
            detail: format!("Трафик IPv4 идёт мимо туннеля (через {src})"),
        },
        (false, _) => Check::Info {
            detail: format!("VPN выключен: трафик идёт напрямую (через {src})"),
        },
    }
}

async fn ipv6_route(connected: bool) -> Check {
    let target = SocketAddr::from((
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        53,
    ));
    let Some(src) = source_address("[::]:0", target).await else {
        return Check::Ok {
            detail: "IPv6 в интернет недоступен — утечки через IPv6 быть не может".into(),
        };
    };
    match (connected, is_tun_address(src)) {
        (true, true) => Check::Ok {
            detail: "Трафик IPv6 идёт через туннель".into(),
        },
        (true, false) => Check::Warning {
            detail: format!(
                "Трафик IPv6 идёт мимо туннеля (через {src}) — сайты могут увидеть ваш адрес"
            ),
        },
        (false, _) => Check::Info {
            detail: "VPN выключен: IPv6 идёт напрямую".into(),
        },
    }
}

/// Чей резолвер ответил на `whoami.akamai.net` и есть ли утечка. При подключённом
/// VPN запросы должны уходить в DoH внутри туннеля: Cloudflare, Google или Quad9 —
/// какой выбран в настройках, плюс запасной.
fn classify_dns(connected: bool, resolver: Option<Ipv4Addr>, remote: &str) -> Check {
    let Some(resolver) = resolver else {
        return Check::Info {
            detail: "Не удалось определить DNS-резолвер".into(),
        };
    };
    if !connected {
        return Check::Info {
            detail: format!("VPN выключен: DNS обслуживает {resolver}"),
        };
    }
    let known = RESOLVERS.iter().find(|r| in_nets(resolver, r.egress));
    let remote = dns::resolver(remote);
    match known {
        Some(r) if r.tunnel => Check::Ok {
            detail: format!("DNS идёт через DoH {} в туннеле", r.title),
        },
        Some(r) => Check::Warning {
            detail: format!(
                "На DNS отвечает {} ({resolver}), а не DoH в туннеле — возможна утечка DNS",
                r.title
            ),
        },
        // Адресов, с которых ходит Quad9, KVT не знает: подтвердить нельзя, но и
        // тревогу поднимать не из-за чего.
        None if remote.is_some_and(|r| r.egress.is_empty()) => Check::Info {
            detail: format!(
                "На DNS отвечает {resolver}. Адресов {} KVT не знает — подтвердить,                  что это DoH в туннеле, нельзя",
                remote.map_or("этого резолвера", |r| r.title)
            ),
        },
        None => Check::Warning {
            detail: format!(
                "На DNS отвечает {resolver}, а не DoH в туннеле — возможна утечка DNS"
            ),
        },
    }
}

async fn dns(connected: bool, remote: &str) -> Check {
    use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
    let start = std::time::Instant::now();
    let lookup =
        tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((WHOAMI, 0))).await;
    let resolver = match lookup {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }),
        _ => None,
    };
    let route = if connected {
        Route::Tunnel
    } else {
        Route::Direct
    };
    let event = |outcome| {
        netlog::Event::new(Origin::App, Purpose::Dns, WHOAMI, route, outcome)
            .detail("проверка утечек")
    };
    netlog::record(match resolver {
        Some(_) => event(Outcome::Ok).ms(start.elapsed()),
        None => event(Outcome::Failed),
    });
    classify_dns(connected, resolver, remote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstat_parsing_is_language_independent() {
        let sample = "\
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1356
  TCP    127.0.0.1:10808        0.0.0.0:0              ПРОСЛУШИВАНИЕ   4242
  TCP    192.168.1.5:50000      0.0.0.0:0              LISTENING       77
  TCP    127.0.0.1:60000        127.0.0.1:443          ESTABLISHED     88
  TCP    [::1]:9000             [::]:0                 LISTENING       99";
        assert_eq!(
            listening_ports(sample),
            [(135, 1356), (10808, 4242), (9000, 99)]
        );
    }

    #[test]
    fn dns_through_chosen_or_reserve_doh_is_ok() {
        let cloudflare = Some(Ipv4Addr::new(172, 68, 1, 1));
        let google = Some(Ipv4Addr::new(74, 125, 18, 5));
        // Выбран Google, но ответил запасной Cloudflare — тоже туннель.
        assert!(matches!(
            classify_dns(true, cloudflare, "google"),
            Check::Ok { .. }
        ));
        assert!(matches!(
            classify_dns(true, google, "google"),
            Check::Ok { .. }
        ));
        assert!(matches!(
            classify_dns(true, google, "cloudflare"),
            Check::Ok { .. }
        ));
    }

    #[test]
    fn dns_through_provider_or_yandex_is_a_leak() {
        let yandex = Some(Ipv4Addr::new(77, 88, 8, 8));
        let provider = Some(Ipv4Addr::new(212, 48, 193, 5));
        assert!(matches!(
            classify_dns(true, yandex, "quad9"),
            Check::Warning { .. }
        ));
        assert!(matches!(
            classify_dns(true, provider, "cloudflare"),
            Check::Warning { .. }
        ));
    }

    #[test]
    fn unknown_resolver_with_quad9_is_not_an_alarm() {
        let unknown = Some(Ipv4Addr::new(149, 112, 112, 10));
        assert!(matches!(
            classify_dns(true, unknown, "quad9"),
            Check::Info { .. }
        ));
    }

    #[test]
    fn dns_without_vpn_is_info() {
        let provider = Some(Ipv4Addr::new(212, 48, 193, 5));
        assert!(matches!(
            classify_dns(false, provider, "cloudflare"),
            Check::Info { .. }
        ));
        assert!(matches!(
            classify_dns(true, None, "cloudflare"),
            Check::Info { .. }
        ));
    }

    /// Отчёт по текущему компьютеру: `cargo test -p kvt-app real_machine -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "проверяет реальный компьютер"]
    async fn real_machine_report() {
        let report = run(false, "cloudflare").await;
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }

    #[tokio::test]
    async fn open_socks5_is_detected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
        });
        assert!(is_open_socks5(port).await);
    }

    #[tokio::test]
    async fn socks5_with_password_is_not_reported() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).await.unwrap();
            // 0xFF — «ни один из предложенных методов не подходит».
            s.write_all(&[0x05, 0xFF]).await.unwrap();
        });
        assert!(!is_open_socks5(port).await);
    }
}
