//! Проверка утечек. Почти всё — локально, без запросов в интернет:
//!
//! - **открытые прокси**: слушающие порты на этом компьютере, которые отвечают
//!   на SOCKS5 без пароля. Через такой порт любая программа узнает IP VPN-сервера
//!   (уязвимость, найденная runetfreedom в 2026 году);
//! - **маршруты IPv4/IPv6**: какой исходный адрес выбирает система для выхода в
//!   интернет (UDP «connect» не отправляет пакетов);
//! - **DNS**: один запрос `whoami.akamai.net` показывает, чей резолвер на самом деле
//!   отвечает на запросы системы.

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
    pub open_proxies: Vec<OpenProxy>,
    pub ipv4_route: Check,
    pub ipv6_route: Check,
    pub dns: Check,
}

pub async fn run(connected: bool) -> LeakReport {
    let (open_proxies, ipv4_route, ipv6_route, dns) = tokio::join!(
        open_proxies(),
        ipv4_route(connected),
        ipv6_route(connected),
        dns(connected)
    );
    LeakReport {
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

/// Диапазоны Cloudflare: DoH 1.1.1.1 ходит в интернет с этих адресов.
const CLOUDFLARE: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];

fn in_cidr(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(net) & mask
}

async fn dns(connected: bool) -> Check {
    let lookup = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host(("whoami.akamai.net", 0)),
    )
    .await;
    let resolver = match lookup {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }),
        _ => None,
    };
    let Some(resolver) = resolver else {
        return Check::Info {
            detail: "Не удалось определить DNS-резолвер".into(),
        };
    };
    let via_doh = CLOUDFLARE
        .iter()
        .any(|(net, p)| in_cidr(resolver, *net, *p));
    match (connected, via_doh) {
        (true, true) => Check::Ok {
            detail: format!("DNS идёт через DoH в туннеле (резолвер {resolver})"),
        },
        (true, false) => Check::Warning {
            detail: format!(
                "DNS отвечает резолвер {resolver}, а не DoH в туннеле — возможна утечка DNS"
            ),
        },
        (false, _) => Check::Info {
            detail: format!("VPN выключен: DNS обслуживает {resolver}"),
        },
    }
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
    fn cloudflare_ranges() {
        assert!(CLOUDFLARE
            .iter()
            .any(|(n, p)| in_cidr(Ipv4Addr::new(172, 68, 1, 1), *n, *p)));
        assert!(!CLOUDFLARE
            .iter()
            .any(|(n, p)| in_cidr(Ipv4Addr::new(77, 88, 8, 8), *n, *p)));
    }

    /// Отчёт по текущему компьютеру: `cargo test -p kvt-app real_machine -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "проверяет реальный компьютер"]
    async fn real_machine_report() {
        let report = run(false).await;
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
