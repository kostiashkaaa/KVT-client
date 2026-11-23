//! WireGuard и AmneziaWG: модель подключения и её проверка.
//!
//! AmneziaWG — тот же WireGuard с дополнительными полями обфускации в секции
//! `[Interface]`. Поэтому одна модель на оба: `awg == None` — обычный WireGuard
//! (штатное ядро sing-box), иначе нужно ядро с AmneziaWG (`CoreKind::SingBoxAwg`).
//!
//! Проверка ([`validate`]) вызывается и разбором `.conf`, и службой (`check_server`):
//! служба получает модель по IPC, минуя парсер, а конфиг ядра работает от SYSTEM.
//! Пределы чисел ниже — защитные пределы KVT, а не правила протокола: в
//! amneziawg-go эти поля — просто `uint32`, а мусорные пакеты шлются с правами службы.

use crate::secret::Secret;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Пиров в одном подключении.
pub const MAX_PEERS: usize = 16;
/// Диапазонов `AllowedIPs` у одного пира.
pub const MAX_ALLOWED_IPS: usize = 256;
/// Адресов интерфейса и адресов DNS.
pub const MAX_ADDRESSES: usize = 8;
/// Длина одной строки `I1`–`I5` (в них бывает целый пакет QUIC в hex).
pub const MAX_CPS_LEN: usize = 8 * 1024;

const MAX_JUNK_COUNT: u64 = 128;
const MAX_PACKET_SIZE: u64 = 1500;
const MAX_CPS_RANDOM: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuard {
    pub private_key: Secret,
    /// Адреса интерфейса в виде CIDR: `10.8.0.2/32`, `fd00::2/128`.
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Адреса DNS из `.conf` (имена и домены поиска отброшены).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    pub peers: Vec<WgPeer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awg: Option<Awg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeer {
    /// base64, 32 байта.
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<Secret>,
    /// Имя или IP сервера без квадратных скобок IPv6.
    pub host: String,
    pub port: u16,
    pub allowed_ips: Vec<String>,
    /// `PersistentKeepalive`: секунды или (только AmneziaWG 3) диапазон `от-до`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<String>,
}

/// Параметры обфускации AmneziaWG. Ключи — имена полей конечной точки sing-box
/// (`jc`, `s1`, `h1`, `header_protection_key`…), значения — проверенный текст.
/// Отсортированная карта: одна и та же настройка — одна и та же строка (ключ
/// дубликатов, `Server` целиком в JSON).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Awg {
    pub params: BTreeMap<String, String>,
    /// Имена параметров из `.conf`, которые KVT не применяет (`J1`–`J3`, `Itime`
    /// из AmneziaWG 1.5 и неизвестные): о них говорит `Server::warnings`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<String>,
}

/// Ключевые параметры (`AwgKind::Key`) — секреты: `{:?}` печатает их как `Secret`.
impl std::fmt::Debug for Awg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: BTreeMap<&str, &str> = self
            .params
            .iter()
            .map(|(k, v)| {
                let secret = AWG_KEYS
                    .iter()
                    .any(|a| a.json == k && matches!(a.kind, AwgKind::Key));
                (k.as_str(), if secret { "***" } else { v.as_str() })
            })
            .collect();
        f.debug_struct("Awg")
            .field("params", &params)
            .field("ignored", &self.ignored)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwgKind {
    /// Десятичное число до предела.
    Count(u64),
    /// Число или диапазон `от-до` (`u32`).
    Range,
    /// Пакет-приманка `I1`–`I5`: теги `<b 0x..>`, `<c>`, `<t>`, `<r N>`, `<rc N>`, `<rd N>`.
    Cps,
    /// base64 от 32 байт.
    Key,
    /// Включено/выключено: хранится только «включено» как `true`.
    Flag,
}

#[derive(Debug, Clone, Copy)]
pub struct AwgKey {
    /// Имя в `.conf` строчными буквами, как его сравнивает парсер.
    pub conf: &'static str,
    /// Имя поля конечной точки sing-box.
    pub json: &'static str,
    pub kind: AwgKind,
}

const fn key(conf: &'static str, json: &'static str, kind: AwgKind) -> AwgKey {
    AwgKey { conf, json, kind }
}

/// Все параметры AmneziaWG (1.0, 2.0, 3.x), которые принимает ядро-форк.
pub const AWG_KEYS: &[AwgKey] = &[
    key("jc", "jc", AwgKind::Count(MAX_JUNK_COUNT)),
    key("jmin", "jmin", AwgKind::Count(MAX_PACKET_SIZE)),
    key("jmax", "jmax", AwgKind::Count(MAX_PACKET_SIZE)),
    key("s1", "s1", AwgKind::Count(MAX_PACKET_SIZE)),
    key("s2", "s2", AwgKind::Count(MAX_PACKET_SIZE)),
    key("s3", "s3", AwgKind::Count(MAX_PACKET_SIZE)),
    key("s4", "s4", AwgKind::Count(MAX_PACKET_SIZE)),
    key("h1", "h1", AwgKind::Range),
    key("h2", "h2", AwgKind::Range),
    key("h3", "h3", AwgKind::Range),
    key("h4", "h4", AwgKind::Range),
    key("i1", "i1", AwgKind::Cps),
    key("i2", "i2", AwgKind::Cps),
    key("i3", "i3", AwgKind::Cps),
    key("i4", "i4", AwgKind::Cps),
    key("i5", "i5", AwgKind::Cps),
    key("headerprotectionkey", "header_protection_key", AwgKind::Key),
    key(
        "contentpaddingaddition",
        "content_padding_addition",
        AwgKind::Range,
    ),
    key("rekeyaftertime", "rekey_after_time", AwgKind::Range),
    key("rekeytimeout", "rekey_timeout", AwgKind::Range),
    key("rejectaftertime", "reject_after_time", AwgKind::Range),
    key("keepalivetimeout", "keepalive_timeout", AwgKind::Range),
    key(
        "maxhandshakeattempts",
        "max_handshake_attempts",
        AwgKind::Range,
    ),
    key("randomtrailers", "random_trailers", AwgKind::Flag),
    key("disablecookies", "disable_cookies", AwgKind::Flag),
];

/// Ключ параметра по его имени в `.conf` (без учёта регистра).
pub fn awg_key_by_conf(name: &str) -> Option<&'static AwgKey> {
    let name = name.to_ascii_lowercase();
    AWG_KEYS.iter().find(|k| k.conf == name)
}

/// Приводит значение к виду, в котором оно хранится. `None` — значение недопустимо.
/// У `Flag` выключенное значение тоже допустимо и даёт `Some("")` — вызывающий
/// такой параметр не сохраняет.
pub fn normalize_awg_value(kind: AwgKind, raw: &str) -> Option<String> {
    let raw = raw.trim();
    match kind {
        AwgKind::Count(max) => {
            let n = parse_decimal(raw)?;
            (n <= max).then(|| n.to_string())
        }
        AwgKind::Range => normalize_range(raw),
        AwgKind::Cps => cps_ok(raw).then(|| raw.to_owned()),
        AwgKind::Key => is_key(raw).then(|| raw.to_owned()),
        AwgKind::Flag => match raw.to_ascii_lowercase().as_str() {
            "true" | "on" | "yes" | "1" => Some("true".to_owned()),
            "false" | "off" | "no" | "0" => Some(String::new()),
            _ => None,
        },
    }
}

fn parse_decimal(s: &str) -> Option<u64> {
    (!s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// `N` или `N-M` (оба до `u32`, `N <= M`); `N-N` записывается как `N`.
pub fn normalize_range(raw: &str) -> Option<String> {
    let max = u64::from(u32::MAX);
    let (a, b) = match raw.split_once('-') {
        Some((a, b)) => (parse_decimal(a.trim())?, Some(parse_decimal(b.trim())?)),
        None => (parse_decimal(raw.trim())?, None),
    };
    if a > max {
        return None;
    }
    match b {
        None => Some(a.to_string()),
        Some(b) if b > max || a > b => None,
        Some(b) if a == b => Some(a.to_string()),
        Some(b) => Some(format!("{a}-{b}")),
    }
}

/// Ключ WireGuard: base64 ровно от 32 байт (44 символа).
pub fn is_key(s: &str) -> bool {
    s.len() == 44 && STANDARD.decode(s).is_ok_and(|b| b.len() == 32)
}

/// Строка пакетов-приманок: подряд теги без пробелов между ними.
fn cps_ok(v: &str) -> bool {
    if v.is_empty() || v.len() > MAX_CPS_LEN {
        return false;
    }
    let mut rest = v;
    while !rest.is_empty() {
        let Some(tail) = rest.strip_prefix('<') else {
            return false;
        };
        let Some((tag, after)) = tail.split_once('>') else {
            return false;
        };
        rest = after;
        let ok = match tag.split_once(' ') {
            None => matches!(tag, "c" | "t"),
            Some(("b", arg)) => arg.strip_prefix("0x").is_some_and(|h| {
                !h.is_empty() && h.len() % 2 == 0 && h.bytes().all(|c| c.is_ascii_hexdigit())
            }),
            Some(("r" | "rc" | "rd", n)) => {
                parse_decimal(n).is_some_and(|n| n >= 1 && n <= u64::from(MAX_CPS_RANDOM))
            }
            Some(_) => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// `10.8.0.2/32` или `fd00::2/128`; без `/маска` — хост (`/32`, `/128`).
/// `None` — не адрес.
pub fn normalize_cidr(s: &str) -> Option<String> {
    let s = s.trim();
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip.trim(), Some(p.trim())),
        None => (s, None),
    };
    let ip: IpAddr = ip.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => max,
        Some(p) => {
            let n = parse_decimal(p)?;
            if n > max {
                return None;
            }
            n
        }
    };
    Some(format!("{ip}/{prefix}"))
}

/// Проверяет модель целиком. `Err` — имя поля (как в `.conf`) для сообщения.
pub fn validate(wg: &WireGuard) -> Result<(), &'static str> {
    if !is_key(wg.private_key.expose()) {
        return Err("PrivateKey");
    }
    if wg.addresses.is_empty() || wg.addresses.len() > MAX_ADDRESSES {
        return Err("Address");
    }
    if wg
        .addresses
        .iter()
        .any(|a| normalize_cidr(a).as_deref() != Some(a))
    {
        return Err("Address");
    }
    if wg.mtu.is_some_and(|m| !(576..=1500).contains(&m)) {
        return Err("MTU");
    }
    if wg.dns.len() > MAX_ADDRESSES || wg.dns.iter().any(|d| d.parse::<IpAddr>().is_err()) {
        return Err("DNS");
    }
    if wg.peers.is_empty() || wg.peers.len() > MAX_PEERS {
        return Err("Peer");
    }
    let is_awg = wg.awg.is_some();
    for peer in &wg.peers {
        validate_peer(peer, is_awg)?;
    }
    if let Some(awg) = &wg.awg {
        validate_awg(awg)?;
    }
    Ok(())
}

fn validate_peer(p: &WgPeer, is_awg: bool) -> Result<(), &'static str> {
    if !is_key(&p.public_key) {
        return Err("PublicKey");
    }
    if p.preshared_key
        .as_ref()
        .is_some_and(|k| !is_key(k.expose()))
    {
        return Err("PresharedKey");
    }
    let host_ok = p.host.parse::<IpAddr>().is_ok()
        || (!p.host.contains(['[', ']'])
            && matches!(url::Host::parse(&p.host), Ok(url::Host::Domain(_))));
    if !host_ok || p.port == 0 {
        return Err("Endpoint");
    }
    if p.allowed_ips.is_empty()
        || p.allowed_ips.len() > MAX_ALLOWED_IPS
        || p.allowed_ips
            .iter()
            .any(|a| normalize_cidr(a).as_deref() != Some(a))
    {
        return Err("AllowedIPs");
    }
    if let Some(k) = &p.keepalive {
        let ok = normalize_range(k).as_deref() == Some(k.as_str())
            && (is_awg || !k.contains('-'))
            && k.split('-')
                .all(|n| n.parse::<u32>().is_ok_and(|n| n <= u32::from(u16::MAX)));
        if !ok {
            return Err("PersistentKeepalive");
        }
    }
    Ok(())
}

fn validate_awg(awg: &Awg) -> Result<(), &'static str> {
    for (name, value) in &awg.params {
        let Some(k) = AWG_KEYS.iter().find(|k| k.json == name) else {
            return Err("AmneziaWG");
        };
        // Выключенный флаг не хранится, поэтому «пусто» — не допустимое значение.
        let canonical = normalize_awg_value(k.kind, value).filter(|v| !v.is_empty());
        if canonical.as_deref() != Some(value.as_str()) {
            return Err(k.json_label());
        }
    }
    let get = |k: &str| awg.params.get(k).and_then(|v| v.parse::<u64>().ok());
    if let (Some(min), Some(max)) = (get("jmin"), get("jmax")) {
        if min > max {
            return Err("Jmin");
        }
    }
    if awg.ignored.len() > 64
        || awg
            .ignored
            .iter()
            .any(|n| n.is_empty() || n.len() > 32 || !n.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return Err("AmneziaWG");
    }
    Ok(())
}

impl AwgKey {
    /// Имя параметра для сообщения об ошибке (`conf` строчными — этого хватит).
    fn json_label(&self) -> &'static str {
        self.conf
    }
}

impl WireGuard {
    /// Секреты подключения — маскировщику журналов.
    pub fn secrets(&self) -> Vec<&str> {
        let mut out = vec![self.private_key.expose()];
        for p in &self.peers {
            if let Some(k) = &p.preshared_key {
                out.push(k.expose());
            }
        }
        if let Some(key) = self
            .awg
            .as_ref()
            .and_then(|a| a.params.get("header_protection_key"))
        {
            out.push(key);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "YEocP0XnRPOZ8pZDsCbSDY5vlNwFJCKjR8+Tl5n0DGM=";
    const KEY2: &str = "sRHdS8ss5pR0yWRe7LFSc2iMv5fHgVuOHEv7Hvaw9Qo=";

    pub(crate) fn sample() -> WireGuard {
        WireGuard {
            private_key: Secret::new(KEY),
            addresses: vec!["10.8.0.2/32".into()],
            mtu: None,
            dns: vec![],
            peers: vec![WgPeer {
                public_key: KEY2.into(),
                preshared_key: None,
                host: "203.0.113.5".into(),
                port: 51820,
                allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                keepalive: Some("25".into()),
            }],
            awg: None,
        }
    }

    #[test]
    fn sample_is_valid() {
        assert_eq!(validate(&sample()), Ok(()));
    }

    #[test]
    fn keys_must_be_32_bytes() {
        assert!(is_key(KEY));
        assert!(!is_key("YEocP0XnRPOZ8pZDsCbSDY5vlNwFJCKjR8+Tl5n0DG="));
        assert!(!is_key(""));
        assert!(!is_key(&"A".repeat(4000)));
        let mut wg = sample();
        wg.private_key = Secret::new("short");
        assert_eq!(validate(&wg), Err("PrivateKey"));
    }

    #[test]
    fn ranges_are_normalized() {
        assert_eq!(normalize_range("5").as_deref(), Some("5"));
        assert_eq!(normalize_range(" 5 - 100 ").as_deref(), Some("5-100"));
        assert_eq!(normalize_range("7-7").as_deref(), Some("7"));
        assert_eq!(normalize_range("5-1"), None);
        assert_eq!(normalize_range("4294967296"), None);
        assert_eq!(normalize_range("-3"), None);
        assert_eq!(normalize_range("1-2-3"), None);
        assert_eq!(normalize_range(""), None);
        assert_eq!(normalize_range("0x10"), None);
    }

    #[test]
    fn counts_have_protective_limits() {
        assert_eq!(
            normalize_awg_value(AwgKind::Count(MAX_JUNK_COUNT), "128").as_deref(),
            Some("128")
        );
        assert_eq!(
            normalize_awg_value(AwgKind::Count(MAX_JUNK_COUNT), "129"),
            None
        );
        assert_eq!(
            normalize_awg_value(AwgKind::Count(MAX_PACKET_SIZE), "007").as_deref(),
            Some("7")
        );
        assert_eq!(
            normalize_awg_value(AwgKind::Count(MAX_PACKET_SIZE), "99999999999999999999"),
            None
        );
        assert_eq!(
            normalize_awg_value(AwgKind::Count(MAX_PACKET_SIZE), "-1"),
            None
        );
    }

    #[test]
    fn decoy_packets_are_strict() {
        for ok in [
            "<b 0x000100002112a442><r 12>",
            "<c><t><r 10><rc 5><rd 3>",
            "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>",
        ] {
            assert!(cps_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "r 12",
            "<r 12",
            "<r 0>",
            "<r 99999>",
            "<b 0xabc>",
            "<b 0x>",
            "<b abcd>",
            "<x 1>",
            "<c> <t>",
            "<c>junk",
            "<r 12><\u{0}>",
        ] {
            assert!(!cps_ok(bad), "{bad:?}");
        }
        assert!(!cps_ok(&format!("<b 0x{}>", "ab".repeat(MAX_CPS_LEN))));
    }

    #[test]
    fn flags_and_cidr() {
        assert_eq!(
            normalize_awg_value(AwgKind::Flag, "On").as_deref(),
            Some("true")
        );
        assert_eq!(
            normalize_awg_value(AwgKind::Flag, "off").as_deref(),
            Some("")
        );
        assert_eq!(normalize_awg_value(AwgKind::Flag, "maybe"), None);
        assert_eq!(normalize_cidr("10.0.0.2").as_deref(), Some("10.0.0.2/32"));
        assert_eq!(normalize_cidr("fd00::2").as_deref(), Some("fd00::2/128"));
        assert_eq!(normalize_cidr("10.0.0.0/33"), None);
        assert_eq!(normalize_cidr("::/129"), None);
        assert_eq!(normalize_cidr("example.com/24"), None);
        assert_eq!(normalize_cidr("10.0.0.1/"), None);
    }

    #[test]
    fn awg_params_must_be_canonical() {
        let mut wg = sample();
        wg.awg = Some(Awg {
            params: [("jc".to_owned(), "5".to_owned())].into(),
            ignored: vec![],
        });
        assert_eq!(validate(&wg), Ok(()));
        for (k, v) in [
            ("jc", "007"),
            ("jc", "129"),
            ("h1", "5-1"),
            ("s1", "-1"),
            ("i1", "<z>"),
            ("random_trailers", ""),
            ("random_trailers", "on"),
            ("header_protection_key", "AAAA"),
            ("evil", "1"),
        ] {
            let mut bad = wg.clone();
            bad.awg = Some(Awg {
                params: [(k.to_owned(), v.to_owned())].into(),
                ignored: vec![],
            });
            assert!(validate(&bad).is_err(), "{k}={v}");
        }
        let mut order = wg.clone();
        order.awg = Some(Awg {
            params: [
                ("jmin".to_owned(), "100".to_owned()),
                ("jmax".to_owned(), "50".to_owned()),
            ]
            .into(),
            ignored: vec![],
        });
        assert_eq!(validate(&order), Err("Jmin"));
    }

    #[test]
    fn peer_and_interface_checks() {
        let mut wg = sample();
        wg.peers[0].port = 0;
        assert_eq!(validate(&wg), Err("Endpoint"));

        let mut wg = sample();
        wg.peers[0].host = "[::1]".into();
        assert_eq!(validate(&wg), Err("Endpoint"));

        let mut wg = sample();
        wg.peers[0].allowed_ips = vec!["0.0.0.0".into()];
        assert_eq!(validate(&wg), Err("AllowedIPs"));

        let mut wg = sample();
        wg.addresses.clear();
        assert_eq!(validate(&wg), Err("Address"));

        let mut wg = sample();
        wg.mtu = Some(100);
        assert_eq!(validate(&wg), Err("MTU"));

        let mut wg = sample();
        wg.dns = vec!["not-an-ip".into()];
        assert_eq!(validate(&wg), Err("DNS"));

        let mut wg = sample();
        wg.peers.clear();
        assert_eq!(validate(&wg), Err("Peer"));
    }

    #[test]
    fn keepalive_range_is_only_for_amnezia() {
        let mut wg = sample();
        wg.peers[0].keepalive = Some("25-35".into());
        assert_eq!(validate(&wg), Err("PersistentKeepalive"));
        wg.awg = Some(Awg {
            params: BTreeMap::new(),
            ignored: vec![],
        });
        assert_eq!(validate(&wg), Ok(()));
        wg.peers[0].keepalive = Some("70000".into());
        assert_eq!(validate(&wg), Err("PersistentKeepalive"));
    }

    #[test]
    fn secrets_include_every_key() {
        let mut wg = sample();
        wg.peers[0].preshared_key = Some(Secret::new(KEY2));
        wg.awg = Some(Awg {
            params: [("header_protection_key".to_owned(), KEY.to_owned())].into(),
            ignored: vec![],
        });
        assert_eq!(wg.secrets(), vec![KEY, KEY2, KEY]);
    }

    #[test]
    fn debug_hides_awg_keys() {
        let awg = Awg {
            params: [
                ("header_protection_key".to_owned(), KEY.to_owned()),
                ("jc".to_owned(), "4".to_owned()),
            ]
            .into(),
            ignored: vec![],
        };
        let text = format!("{awg:?}");
        assert!(!text.contains(KEY), "{text}");
        assert!(text.contains("\"jc\": \"4\""), "{text}");
    }

    #[test]
    fn diagnostics_json_hides_header_protection_key() {
        // `/` делит ключ на части короче порога эвристики токенов.
        let key = "abcdefghij0123456789/ABCDEFGHIJ0123456789ab=";
        let config = serde_json::json!({ "endpoints": [{ "header_protection_key": key }] });
        let text = crate::redact::json(&config).to_string();
        assert!(!text.contains(key), "{text}");
    }
}
