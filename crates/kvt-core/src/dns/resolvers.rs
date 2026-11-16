//! Каталог публичных резолверов (адреса, сети, DoT и DoH), имена для проверки DNS и
//! признаки адресов: сеть резолвера, FakeIP, заглушка. Никаких запросов здесь нет.

use super::Via;
use serde::Serialize;
use std::net::Ipv4Addr;

/// Имя, в ответ на которое Akamai присылает адрес спросившего его резолвера.
pub const WHOAMI: &str = "whoami.akamai.net";

/// Заблокированные в России сайты на разной инфраструктуре (Meta и Cloudflare).
pub const SPOOF_DOMAINS: [&str; 2] = ["facebook.com", "rutracker.org"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub host: &'static str,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolver {
    pub id: &'static str,
    /// Название; на английском — через [`title_text`].
    #[serde(serialize_with = "ser_title")]
    pub title: &'static str,
    pub udp: Ipv4Addr,
    pub dot: Endpoint,
    /// DoH по адресу `https://<host>/dns-query`, если резолвер его поддерживает.
    pub doh: Option<Endpoint>,
    /// Можно указывать в конфиге ядра как DoH по IP (сертификат выдан и на IP).
    pub tunnel: bool,
    /// Откуда этот резолвер ходит к авторитетным серверам. Пусто — неизвестно.
    #[serde(skip)]
    pub egress: &'static [(Ipv4Addr, u8)],
}

/// Название резолвера на текущем языке (по-русски в каталоге только «Яндекс»).
pub fn title_text(title: &str) -> &str {
    match title {
        "Яндекс" => crate::i18n::tr("Яндекс", "Yandex"),
        other => other,
    }
}

pub(super) fn ser_title<S: serde::Serializer>(
    title: &&'static str,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(title_text(title))
}

impl Resolver {
    pub fn endpoint(&self, via: Via) -> Option<Endpoint> {
        match via {
            Via::Udp => None,
            Via::Dot => Some(self.dot),
            Via::Doh => self.doh,
        }
    }
}

const fn ep(host: &'static str, a: u8, b: u8, c: u8, d: u8) -> Endpoint {
    Endpoint {
        host,
        ip: Ipv4Addr::new(a, b, c, d),
    }
}

/// Сети Cloudflare (cloudflare.com/ips-v4).
pub const CLOUDFLARE_NETS: &[(Ipv4Addr, u8)] = &[
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

/// Сети, из которых работает Google Public DNS.
const GOOGLE_NETS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(8, 8, 4, 0), 24),
    (Ipv4Addr::new(8, 8, 8, 0), 24),
    (Ipv4Addr::new(64, 233, 160, 0), 19),
    (Ipv4Addr::new(66, 249, 64, 0), 19),
    (Ipv4Addr::new(74, 125, 0, 0), 16),
    (Ipv4Addr::new(108, 177, 0, 0), 17),
    (Ipv4Addr::new(142, 250, 0, 0), 15),
    (Ipv4Addr::new(172, 217, 0, 0), 16),
    (Ipv4Addr::new(172, 253, 0, 0), 16),
    (Ipv4Addr::new(173, 194, 0, 0), 16),
    (Ipv4Addr::new(192, 178, 0, 0), 15),
    (Ipv4Addr::new(209, 85, 128, 0), 17),
    (Ipv4Addr::new(216, 239, 32, 0), 19),
];

/// Сети Яндекса (AS13238).
pub(super) const YANDEX_NETS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(5, 45, 192, 0), 18),
    (Ipv4Addr::new(5, 255, 192, 0), 18),
    (Ipv4Addr::new(37, 9, 64, 0), 18),
    (Ipv4Addr::new(37, 140, 128, 0), 18),
    (Ipv4Addr::new(77, 88, 0, 0), 18),
    (Ipv4Addr::new(84, 252, 160, 0), 19),
    (Ipv4Addr::new(87, 250, 224, 0), 19),
    (Ipv4Addr::new(93, 158, 128, 0), 18),
    (Ipv4Addr::new(95, 108, 128, 0), 17),
    (Ipv4Addr::new(141, 8, 128, 0), 18),
    (Ipv4Addr::new(178, 154, 128, 0), 18),
    (Ipv4Addr::new(213, 180, 192, 0), 19),
];

/// Резолверы, которые проверяет KVT. Первый — для прямых (российских) сайтов
/// по умолчанию: он отдаёт ближайшие узлы российских CDN.
pub const RESOLVERS: &[Resolver] = &[
    Resolver {
        id: "yandex",
        title: "Яндекс",
        udp: Ipv4Addr::new(77, 88, 8, 8),
        dot: ep("common.dot.dns.yandex.net", 77, 88, 8, 8),
        doh: None,
        tunnel: false,
        egress: YANDEX_NETS,
    },
    Resolver {
        id: "cloudflare",
        title: "Cloudflare",
        udp: Ipv4Addr::new(1, 1, 1, 1),
        dot: ep("one.one.one.one", 1, 1, 1, 1),
        doh: Some(ep("cloudflare-dns.com", 1, 1, 1, 1)),
        tunnel: true,
        egress: CLOUDFLARE_NETS,
    },
    Resolver {
        id: "google",
        title: "Google",
        udp: Ipv4Addr::new(8, 8, 8, 8),
        dot: ep("dns.google", 8, 8, 8, 8),
        doh: Some(ep("dns.google", 8, 8, 8, 8)),
        tunnel: true,
        egress: GOOGLE_NETS,
    },
    Resolver {
        id: "quad9",
        title: "Quad9",
        udp: Ipv4Addr::new(9, 9, 9, 9),
        dot: ep("dns.quad9.net", 9, 9, 9, 9),
        doh: Some(ep("dns.quad9.net", 9, 9, 9, 9)),
        tunnel: true,
        egress: &[],
    },
    Resolver {
        id: "adguard",
        title: "AdGuard",
        udp: Ipv4Addr::new(94, 140, 14, 14),
        dot: ep("dns.adguard-dns.com", 94, 140, 14, 14),
        doh: Some(ep("dns.adguard-dns.com", 94, 140, 14, 14)),
        tunnel: false,
        egress: &[],
    },
];

pub fn resolver(id: &str) -> Option<&'static Resolver> {
    RESOLVERS.iter().find(|r| r.id == id)
}

pub fn in_nets(ip: Ipv4Addr, nets: &[(Ipv4Addr, u8)]) -> bool {
    nets.iter().any(|&(net, prefix)| {
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
        u32::from(ip) & mask == u32::from(net) & mask
    })
}

pub(super) fn same_24(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    a.octets()[..3] == b.octets()[..3]
}

/// Диапазон FakeIP: так sing-box, podkop и Clash на роутере помечают домены,
/// которые сами ведут через свой VPN. Это не подмена провайдером.
pub(super) fn is_fake_ip(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (18..20).contains(&o[1])
}

/// Адрес, которого не бывает у публичного сайта: так выглядят заглушки.
pub(super) fn is_bogon(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 198 && (18..20).contains(&o[1]))
        || o[0] >= 240
}
