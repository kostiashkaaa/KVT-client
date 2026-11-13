//! Проверка DNS: какие резолверы доступны из текущей сети, перехватывает ли
//! провайдер запросы к ним и подменяет ли ответы для заблокированных сайтов.
//!
//! Здесь только данные и выводы. Запросы отправляет приложение и передаёт сюда
//! наблюдения ([`Observations`]), поэтому анализ покрыт тестами без сети.
//!
//! Как это определяется:
//!
//! - **перехват**: `whoami.akamai.net` возвращает адрес резолвера, который на самом
//!   деле спросил Akamai. Если по UDP «Google» отвечает адресом провайдера, а по
//!   DoH (его не подделать без сертификата) — адресом Google, провайдер
//!   перехватывает порт 53;
//! - **подмена**: два заблокированных сайта с разной инфраструктурой. Честный
//!   резолвер вернёт им разные адреса, а заглушка провайдера — один и тот же адрес
//!   страницы блокировки (или адрес из частной сети).

pub mod names;
pub mod wire;

use crate::i18n::tr;
use crate::trf;
use serde::Serialize;
use std::net::Ipv4Addr;

pub use wire::Answer;

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

fn ser_title<S: serde::Serializer>(title: &&'static str, s: S) -> Result<S::Ok, S::Error> {
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
const YANDEX_NETS: &[(Ipv4Addr, u8)] = &[
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

fn same_24(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    a.octets()[..3] == b.octets()[..3]
}

/// Диапазон FakeIP: так sing-box, podkop и Clash на роутере помечают домены,
/// которые сами ведут через свой VPN. Это не подмена провайдером.
fn is_fake_ip(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (18..20).contains(&o[1])
}

/// Адрес, которого не бывает у публичного сайта: так выглядят заглушки.
fn is_bogon(ip: Ipv4Addr) -> bool {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Udp,
    Dot,
    Doh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    Answer { answer: Answer, ms: u64 },
    Timeout,
    Failed(String),
}

impl QueryResult {
    fn answer(&self) -> Option<&Answer> {
        match self {
            QueryResult::Answer { answer, .. } => Some(answer),
            _ => None,
        }
    }

    /// Адрес из ответа на `whoami.akamai.net`.
    fn egress(&self) -> Option<Ipv4Addr> {
        self.answer().and_then(|a| a.a.first().copied())
    }
}

/// Кого спрашивали: DNS из настроек сети или резолвер из каталога.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    System,
    Resolver(&'static str, Via),
}

#[derive(Debug, Clone, Default)]
pub struct Observations {
    /// DNS-сервер из настроек сети (обычно роутер или провайдер).
    pub system_server: Option<Ipv4Addr>,
    /// `whoami.akamai.net` через DNS из настроек сети.
    pub system_whoami: Option<QueryResult>,
    /// `whoami.akamai.net`: каждый резолвер каждым способом.
    pub whoami: Vec<(&'static str, Via, QueryResult)>,
    /// Домены из [`SPOOF_DOMAINS`].
    pub spoof: Vec<(&'static str, Source, QueryResult)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PathStatus {
    Works {
        ms: u64,
    },
    /// Отвечает не тот, кого спрашивали: провайдер перехватывает запросы.
    Intercepted {
        ms: u64,
        by: Ipv4Addr,
    },
    /// Нет ответа — скорее всего, порт или адрес заблокирован.
    Blocked,
    Failed {
        reason: String,
    },
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolverReport {
    pub id: &'static str,
    #[serde(serialize_with = "ser_title")]
    pub title: &'static str,
    pub udp: PathStatus,
    pub dot: PathStatus,
    pub doh: PathStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpoofKind {
    /// Адрес из частной сети или один адрес для разных сайтов — страница блокировки.
    Stub,
    /// Адрес FakeIP (198.18.0.0/15): роутер сам ведёт сайт через свой VPN.
    FakeIp,
    /// «Такого сайта нет» или отказ, хотя зашифрованный DNS его находит.
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpoofFinding {
    pub domain: &'static str,
    /// Кто подменил: «DNS сети» или «Google (UDP)».
    pub source: String,
    pub kind: SpoofKind,
    pub got: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Ok,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsReport {
    pub resolvers: Vec<ResolverReport>,
    pub system_server: Option<Ipv4Addr>,
    /// Резолвер, который на самом деле обслуживает DNS из настроек сети.
    pub system_egress: Option<Ipv4Addr>,
    pub interception: bool,
    /// Подмена провайдером (без FakeIP роутера).
    pub spoofing: Vec<SpoofFinding>,
    /// DNS сети отдаёт адреса FakeIP: на роутере работает podkop или похожий обход.
    pub fake_ip: bool,
    /// Хотя бы один зашифрованный DNS (DoH/DoT) работает напрямую.
    pub encrypted_available: bool,
    /// Резолвер для прямых сайтов (id из [`RESOLVERS`]).
    pub recommended_local: &'static str,
    pub tone: Tone,
    pub title: String,
    pub detail: String,
}

fn path_status(
    resolver: &Resolver,
    via: Via,
    result: Option<&QueryResult>,
    system: Option<Ipv4Addr>,
    encrypted_egress: Option<Ipv4Addr>,
) -> PathStatus {
    match result {
        None => PathStatus::NotChecked,
        Some(QueryResult::Timeout) => PathStatus::Blocked,
        Some(QueryResult::Failed(reason)) => PathStatus::Failed {
            reason: reason.clone(),
        },
        Some(QueryResult::Answer { answer, ms }) => {
            let ms = *ms;
            let Some(egress) = answer.a.first().copied() else {
                return PathStatus::Works { ms };
            };
            // DoH и DoT защищены сертификатом: подменить их ответ провайдер не может.
            if via == Via::Udp && intercepted(resolver, egress, system, encrypted_egress) {
                PathStatus::Intercepted { ms, by: egress }
            } else {
                PathStatus::Works { ms }
            }
        }
    }
}

/// Выводы делаются осторожно: таблицы сетей могут устареть, поэтому перехват
/// засчитывается, только если его подтверждает второй признак.
fn intercepted(
    resolver: &Resolver,
    egress: Ipv4Addr,
    system: Option<Ipv4Addr>,
    encrypted_egress: Option<Ipv4Addr>,
) -> bool {
    let like_system = system.is_some_and(|s| same_24(s, egress));
    if !resolver.egress.is_empty() {
        if in_nets(egress, resolver.egress) {
            return false;
        }
        return like_system || encrypted_egress.is_some_and(|e| in_nets(e, resolver.egress));
    }
    like_system && encrypted_egress.is_some_and(|e| !same_24(e, egress))
}

fn source_title(source: Source) -> String {
    match source {
        Source::System => crate::i18n::tr("DNS сети", "Network DNS").into(),
        Source::Resolver(id, via) => {
            let title = resolver(id).map_or(id, |r| title_text(r.title));
            let via = match via {
                Via::Udp => "UDP",
                Via::Dot => "DoT",
                Via::Doh => "DoH",
            };
            format!("{title} ({via})")
        }
    }
}

fn spoof_findings(obs: &Observations) -> Vec<SpoofFinding> {
    let encrypted = |s: Source| matches!(s, Source::Resolver(_, Via::Doh | Via::Dot));
    // Эталон — зашифрованный ответ, в нём есть адреса.
    let reference = |domain: &str| -> Option<Vec<Ipv4Addr>> {
        obs.spoof
            .iter()
            .filter(|(d, s, _)| *d == domain && encrypted(*s))
            .filter_map(|(_, _, r)| r.answer())
            .find(|a| !a.a.is_empty())
            .map(|a| a.a.clone())
    };
    let references: Vec<Option<Vec<Ipv4Addr>>> = SPOOF_DOMAINS.into_iter().map(reference).collect();
    let reference_disjoint = match (&references[0], &references[1]) {
        (Some(a), Some(b)) => !a.iter().any(|ip| b.contains(ip)),
        // Без эталона полагаемся на то, что у Meta и Cloudflare нет общих адресов.
        _ => true,
    };

    let mut sources: Vec<Source> = Vec::new();
    for (_, s, _) in &obs.spoof {
        if !encrypted(*s) && !sources.contains(s) {
            sources.push(*s);
        }
    }

    let mut out = Vec::new();
    for source in sources {
        let answers: Vec<Option<&Answer>> = SPOOF_DOMAINS
            .into_iter()
            .map(|d| {
                obs.spoof
                    .iter()
                    .find(|(dd, s, _)| *dd == d && *s == source)
                    .and_then(|(_, _, r)| r.answer())
            })
            .collect();
        let shared: Vec<Ipv4Addr> = match (answers[0], answers[1]) {
            (Some(a), Some(b)) if reference_disjoint => {
                a.a.iter().filter(|ip| b.a.contains(ip)).copied().collect()
            }
            _ => Vec::new(),
        };
        for (i, domain) in SPOOF_DOMAINS.into_iter().enumerate() {
            let Some(answer) = answers[i] else { continue };
            let kind = if !answer.a.is_empty() && answer.a.iter().all(|ip| is_fake_ip(*ip)) {
                Some(SpoofKind::FakeIp)
            } else if answer.a.iter().any(|ip| is_bogon(*ip)) || !shared.is_empty() {
                Some(SpoofKind::Stub)
            } else if matches!(answer.rcode, wire::RCODE_NXDOMAIN | wire::RCODE_REFUSED)
                && references[i].is_some()
            {
                Some(SpoofKind::Denied)
            } else {
                None
            };
            if let Some(kind) = kind {
                out.push(SpoofFinding {
                    domain,
                    source: source_title(source),
                    kind,
                    got: answer.a.clone(),
                });
            }
        }
    }
    out
}

pub fn analyze(obs: &Observations) -> DnsReport {
    let system_egress = obs.system_whoami.as_ref().and_then(QueryResult::egress);
    let find = |id: &str, via: Via| {
        obs.whoami
            .iter()
            .find(|(i, v, _)| *i == id && *v == via)
            .map(|(_, _, r)| r)
    };

    let resolvers: Vec<ResolverReport> = RESOLVERS
        .iter()
        .map(|r| {
            let encrypted_egress = [Via::Doh, Via::Dot]
                .into_iter()
                .find_map(|via| find(r.id, via).and_then(QueryResult::egress));
            let status =
                |via| path_status(r, via, find(r.id, via), system_egress, encrypted_egress);
            ResolverReport {
                id: r.id,
                title: r.title,
                udp: status(Via::Udp),
                dot: status(Via::Dot),
                doh: status(Via::Doh),
            }
        })
        .collect();

    let interception = resolvers
        .iter()
        .any(|r| matches!(r.udp, PathStatus::Intercepted { .. }));
    let interceptor = resolvers.iter().find_map(|r| match r.udp {
        PathStatus::Intercepted { by, .. } => Some(by),
        _ => None,
    });
    let encrypted_available = resolvers.iter().any(|r| {
        matches!(r.dot, PathStatus::Works { .. }) || matches!(r.doh, PathStatus::Works { .. })
    });
    // Для прямых сайтов годится любой резолвер, который отвечает сам; Яндекс — первый.
    let recommended_local = resolvers
        .iter()
        .find(|r| matches!(r.udp, PathStatus::Works { .. }))
        .map_or(RESOLVERS[0].id, |r| r.id);
    let (fake, spoofing): (Vec<_>, Vec<_>) = spoof_findings(obs)
        .into_iter()
        .partition(|f| f.kind == SpoofKind::FakeIp);
    let fake_ip = !fake.is_empty();

    let (tone, title, mut detail) = match (interception, spoofing.is_empty()) {
        (true, false) => (
            Tone::Warning,
            tr(
                "Провайдер перехватывает DNS и подменяет ответы",
                "Your ISP intercepts DNS and spoofs answers",
            )
            .to_owned(),
            trf!(
                "На запросы к публичным DNS по UDP отвечает сервер провайдера ({}), а для \
                 заблокированных сайтов он возвращает адрес заглушки.",
                "Queries to public DNS over UDP are answered by your ISP's server ({}), and for \
                 blocked sites it returns a block-page address.",
                interceptor.map(|ip| ip.to_string()).unwrap_or_default()
            ),
        ),
        (true, true) => (
            Tone::Warning,
            tr(
                "Провайдер перехватывает DNS-запросы",
                "Your ISP intercepts DNS queries",
            )
            .to_owned(),
            trf!(
                "На запросы к публичным DNS по UDP отвечает сервер провайдера ({}). Подмены \
                 ответов для проверочных сайтов не нашлось.",
                "Queries to public DNS over UDP are answered by your ISP's server ({}). No \
                 spoofed answers were found for the test sites.",
                interceptor.map(|ip| ip.to_string()).unwrap_or_default()
            ),
        ),
        (false, false) => (
            Tone::Warning,
            tr(
                "DNS подменяет ответы для заблокированных сайтов",
                "DNS spoofs answers for blocked sites",
            )
            .to_owned(),
            trf!(
                "{} возвращает адрес заглушки вместо настоящего адреса сайта.",
                "{} returns a block-page address instead of the site's real address.",
                spoofing[0].source
            ),
        ),
        (false, true) if fake_ip => (
            Tone::Ok,
            tr(
                "На роутере работает обход блокировок",
                "Your router bypasses blocks",
            )
            .to_owned(),
            tr(
                "DNS сети отдаёт заблокированным сайтам адреса FakeIP (198.18.x.x) — так работают \
                 podkop и sing-box: роутер сам ведёт эти сайты через свой VPN. Подмены провайдером \
                 и перехвата запросов не обнаружено. С KVT это не конфликтует: при подключении DNS \
                 идёт через DoH в туннеле KVT.",
                "The network DNS gives blocked sites FakeIP addresses (198.18.x.x) — that's how \
                 podkop and sing-box work: the router routes these sites through its own VPN. No ISP \
                 spoofing or query interception was found. This doesn't conflict with KVT: when \
                 connected, DNS goes over DoH inside the KVT tunnel.",
            )
            .to_owned(),
        ),
        (false, true) => (
            Tone::Ok,
            tr("DNS работает честно", "DNS is honest").to_owned(),
            tr(
                "Перехвата запросов и подмены ответов не обнаружено.",
                "No query interception or spoofed answers found.",
            )
            .to_owned(),
        ),
    };
    if tone == Tone::Warning {
        detail.push_str(tr(
            " При подключении через KVT это не мешает: DNS шифруется (DoH) и идёт внутри туннеля.",
            " This doesn't matter when connected through KVT: DNS is encrypted (DoH) and goes inside the tunnel.",
        ));
    }
    if !encrypted_available {
        detail.push_str(tr(
            " Зашифрованный DNS (DoH и DoT) напрямую недоступен — похоже, провайдер его блокирует.",
            " Encrypted DNS (DoH and DoT) isn't reachable directly — your ISP seems to block it.",
        ));
    }

    DnsReport {
        resolvers,
        system_server: obs.system_server,
        system_egress,
        interception,
        spoofing,
        fake_ip,
        encrypted_available,
        recommended_local,
        tone,
        title,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISP: Ipv4Addr = Ipv4Addr::new(212, 48, 193, 5);

    fn ok(ips: &[Ipv4Addr]) -> QueryResult {
        QueryResult::Answer {
            answer: Answer {
                rcode: 0,
                a: ips.to_vec(),
                ..Answer::default()
            },
            ms: 20,
        }
    }

    fn rcode(code: u8) -> QueryResult {
        QueryResult::Answer {
            answer: Answer {
                rcode: code,
                ..Answer::default()
            },
            ms: 20,
        }
    }

    /// Честная сеть: каждый резолвер отвечает из своих сетей.
    fn honest() -> Observations {
        let egress = |id: &str| match id {
            "yandex" => Ipv4Addr::new(87, 250, 250, 1),
            "cloudflare" => Ipv4Addr::new(172, 68, 4, 10),
            "google" => Ipv4Addr::new(172, 253, 1, 2),
            "quad9" => Ipv4Addr::new(74, 63, 16, 1),
            _ => Ipv4Addr::new(94, 140, 15, 1),
        };
        let mut obs = Observations {
            system_server: Some(Ipv4Addr::new(192, 168, 1, 1)),
            system_whoami: Some(ok(&[ISP])),
            ..Default::default()
        };
        for r in RESOLVERS {
            for via in [Via::Udp, Via::Dot, Via::Doh] {
                obs.whoami.push((r.id, via, ok(&[egress(r.id)])));
            }
        }
        let fb = [Ipv4Addr::new(157, 240, 205, 35)];
        let rt = [
            Ipv4Addr::new(104, 21, 32, 39),
            Ipv4Addr::new(172, 67, 182, 196),
        ];
        for source in [
            Source::System,
            Source::Resolver("google", Via::Udp),
            Source::Resolver("cloudflare", Via::Doh),
        ] {
            obs.spoof.push((SPOOF_DOMAINS[0], source, ok(&fb)));
            obs.spoof.push((SPOOF_DOMAINS[1], source, ok(&rt)));
        }
        obs
    }

    fn set_whoami(obs: &mut Observations, id: &str, via: Via, r: QueryResult) {
        for entry in &mut obs.whoami {
            if entry.0 == id && entry.1 == via {
                entry.2 = r.clone();
            }
        }
    }

    fn set_spoof(obs: &mut Observations, source: Source, domain: &str, r: QueryResult) {
        for entry in &mut obs.spoof {
            if entry.0 == domain && entry.1 == source {
                entry.2 = r.clone();
            }
        }
    }

    #[test]
    fn honest_network() {
        let report = analyze(&honest());
        assert_eq!(report.tone, Tone::Ok);
        assert!(!report.interception);
        assert!(report.spoofing.is_empty());
        assert!(report.encrypted_available);
        assert_eq!(report.recommended_local, "yandex");
        assert!(report
            .resolvers
            .iter()
            .all(|r| matches!(r.udp, PathStatus::Works { .. })));
    }

    #[test]
    fn transparent_proxy_on_port_53() {
        let mut obs = honest();
        for r in RESOLVERS {
            set_whoami(&mut obs, r.id, Via::Udp, ok(&[ISP]));
        }
        let report = analyze(&obs);
        assert!(report.interception);
        assert_eq!(report.tone, Tone::Warning);
        for r in &report.resolvers {
            assert_eq!(
                r.udp,
                PathStatus::Intercepted { ms: 20, by: ISP },
                "{}",
                r.id
            );
        }
        // Никто не отвечает сам — для прямых сайтов остаётся Яндекс (ответит провайдер).
        assert_eq!(report.recommended_local, "yandex");
    }

    /// Ответ не из сетей Google, но DoH тоже недоступен и с провайдером не совпадает:
    /// таблица могла устареть — перехват не засчитываем.
    #[test]
    fn unknown_egress_without_confirmation_is_not_interception() {
        let mut obs = honest();
        set_whoami(
            &mut obs,
            "google",
            Via::Udp,
            ok(&[Ipv4Addr::new(35, 1, 2, 3)]),
        );
        set_whoami(&mut obs, "google", Via::Doh, QueryResult::Timeout);
        set_whoami(&mut obs, "google", Via::Dot, QueryResult::Timeout);
        let report = analyze(&obs);
        assert!(!report.interception);
    }

    #[test]
    fn unknown_egress_confirmed_by_doh_is_interception() {
        let mut obs = honest();
        let other = Ipv4Addr::new(35, 1, 2, 3);
        set_whoami(&mut obs, "google", Via::Udp, ok(&[other]));
        let report = analyze(&obs);
        let google = report.resolvers.iter().find(|r| r.id == "google").unwrap();
        assert_eq!(google.udp, PathStatus::Intercepted { ms: 20, by: other });
    }

    /// Windows настроена на 8.8.8.8: DNS сети и Google совпадают, но это не перехват.
    #[test]
    fn system_dns_set_to_google_is_not_interception() {
        let mut obs = honest();
        let g = Ipv4Addr::new(172, 253, 1, 2);
        obs.system_whoami = Some(ok(&[g]));
        let report = analyze(&obs);
        assert!(!report.interception);
    }

    #[test]
    fn blocked_encrypted_dns() {
        let mut obs = honest();
        for r in RESOLVERS {
            set_whoami(&mut obs, r.id, Via::Dot, QueryResult::Timeout);
            set_whoami(&mut obs, r.id, Via::Doh, QueryResult::Failed("tls".into()));
        }
        let report = analyze(&obs);
        assert!(!report.encrypted_available);
        assert!(report.detail.contains("DoH и DoT"));
        let cf = &report.resolvers[1];
        assert_eq!(cf.dot, PathStatus::Blocked);
        assert!(matches!(cf.doh, PathStatus::Failed { .. }));
    }

    #[test]
    fn stub_address_for_both_sites() {
        let mut obs = honest();
        let stub = Ipv4Addr::new(195, 208, 152, 206);
        for d in SPOOF_DOMAINS {
            set_spoof(&mut obs, Source::System, d, ok(&[stub]));
        }
        let report = analyze(&obs);
        assert_eq!(report.spoofing.len(), 2);
        assert!(report
            .spoofing
            .iter()
            .all(|f| f.kind == SpoofKind::Stub && f.source == "DNS сети"));
        assert_eq!(
            report.title,
            "DNS подменяет ответы для заблокированных сайтов"
        );
    }

    /// Роутер с podkop: FakeIP — не подмена, а свой обход.
    #[test]
    fn router_fake_ip_is_not_spoofing() {
        let mut obs = honest();
        let fake = [
            Ipv4Addr::new(198, 18, 11, 149),
            Ipv4Addr::new(198, 18, 10, 173),
        ];
        for (domain, ip) in SPOOF_DOMAINS.into_iter().zip(fake) {
            set_spoof(&mut obs, Source::System, domain, ok(&[ip]));
        }
        let report = analyze(&obs);
        assert!(report.fake_ip);
        assert!(report.spoofing.is_empty());
        assert_eq!(report.tone, Tone::Ok);
        assert_eq!(report.title, "На роутере работает обход блокировок");
    }

    #[test]
    fn private_address_is_stub() {
        let mut obs = honest();
        set_spoof(
            &mut obs,
            Source::Resolver("google", Via::Udp),
            SPOOF_DOMAINS[0],
            ok(&[Ipv4Addr::new(10, 10, 34, 34)]),
        );
        let report = analyze(&obs);
        assert_eq!(report.spoofing.len(), 1);
        assert_eq!(report.spoofing[0].source, "Google (UDP)");
    }

    #[test]
    fn nxdomain_while_doh_resolves() {
        let mut obs = honest();
        set_spoof(
            &mut obs,
            Source::System,
            SPOOF_DOMAINS[1],
            rcode(wire::RCODE_NXDOMAIN),
        );
        let report = analyze(&obs);
        assert_eq!(report.spoofing.len(), 1);
        assert_eq!(report.spoofing[0].kind, SpoofKind::Denied);
        assert_eq!(report.spoofing[0].domain, "rutracker.org");
    }

    #[test]
    fn encrypted_answers_are_never_reported() {
        let mut obs = honest();
        let stub = Ipv4Addr::new(10, 0, 0, 1);
        for d in SPOOF_DOMAINS {
            set_spoof(
                &mut obs,
                Source::Resolver("cloudflare", Via::Doh),
                d,
                ok(&[stub]),
            );
        }
        assert!(analyze(&obs)
            .spoofing
            .iter()
            .all(|f| !f.source.contains("DoH")));
    }

    #[test]
    fn nets() {
        assert!(in_nets(Ipv4Addr::new(172, 68, 1, 1), CLOUDFLARE_NETS));
        assert!(!in_nets(Ipv4Addr::new(77, 88, 8, 8), CLOUDFLARE_NETS));
        assert!(in_nets(Ipv4Addr::new(77, 88, 8, 8), YANDEX_NETS));
        assert!(in_nets(
            Ipv4Addr::new(1, 2, 3, 4),
            &[(Ipv4Addr::UNSPECIFIED, 0)]
        ));
        assert!(is_bogon(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_bogon(Ipv4Addr::new(100, 128, 0, 1)));
    }
}
