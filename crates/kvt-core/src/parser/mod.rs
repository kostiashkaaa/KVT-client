//! Разбор ссылок и тел подписок. Вход недоверенный: никаких паник, лимиты на
//! размер, ошибки не содержат секретов из исходной строки.

mod hysteria2;
mod shadowsocks;
mod stream;
mod trojan;
mod vless;

use crate::model::Server;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use thiserror::Error;
use url::Url;

/// Больше строк в подписке не разбираем — защита от «бомб».
pub const MAX_SUBSCRIPTION_LINES: usize = 10_000;
/// Максимальная длина одной ссылки.
pub const MAX_URI_LEN: usize = 8 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("неизвестная схема ссылки «{0}»")]
    UnknownScheme(String),
    #[error("ссылка повреждена")]
    InvalidUrl,
    #[error("ссылка слишком длинная")]
    TooLong,
    #[error("не хватает поля «{0}»")]
    MissingField(&'static str),
    #[error("некорректное поле «{field}»: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("не поддерживается: {0}")]
    Unsupported(&'static str),
}

/// Результат разбора одной строки подписки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Server(Box<Server>),
    /// Служебная «запись» провайдера вроде «Осталось 10 ГБ» с адресом 0.0.0.0.
    /// Показывается как сообщение, а не как сервер.
    Info(String),
}

#[derive(Debug, Default)]
pub struct SubscriptionContent {
    pub servers: Vec<Server>,
    pub info: Vec<String>,
    /// Номер строки (с 1) и ошибка. Саму строку не храним — в ней секреты.
    pub errors: Vec<(usize, ParseError)>,
    /// Сколько точных дубликатов (адрес, порт, протокол, учётные данные) выброшено.
    pub duplicates: usize,
}

/// Разбирает одну ссылку `scheme://...`.
pub fn parse_uri(input: &str) -> Result<Entry, ParseError> {
    let input = input.trim();
    if input.len() > MAX_URI_LEN {
        return Err(ParseError::TooLong);
    }
    let scheme = input
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or(ParseError::InvalidUrl)?;

    let server = match scheme.as_str() {
        "vless" => vless::parse(input)?,
        "trojan" => trojan::parse(input)?,
        "ss" => shadowsocks::parse(input)?,
        "hysteria2" | "hy2" => hysteria2::parse(input)?,
        "vmess" => return Err(ParseError::Unsupported("VMess пока не поддерживается")),
        other => {
            let shown: String = other.chars().take(16).collect();
            return Err(ParseError::UnknownScheme(shown));
        }
    };

    if is_info_entry(&server) {
        return Ok(Entry::Info(server.name));
    }
    Ok(Entry::Server(Box::new(server)))
}

/// Разбирает тело подписки: список ссылок, в том числе в base64.
pub fn parse_subscription_body(body: &str) -> SubscriptionContent {
    let mut out = SubscriptionContent::default();
    let trimmed = body.trim();

    let decoded;
    let text = if trimmed.contains("://") {
        trimmed
    } else if let Some(bytes) = decode_base64_lenient(trimmed) {
        decoded = String::from_utf8_lossy(&bytes).into_owned();
        decoded.as_str()
    } else {
        trimmed
    };

    if text.starts_with('{') || text.starts_with('[') || text.contains("\nproxies:") {
        out.errors.push((
            0,
            ParseError::Unsupported("JSON/Clash-подписки появятся в следующей версии"),
        ));
        return out;
    }

    let mut seen = std::collections::HashSet::new();
    for (idx, line) in text.lines().enumerate().take(MAX_SUBSCRIPTION_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || !line.contains("://") {
            continue;
        }
        match parse_uri(line) {
            Ok(Entry::Server(server)) => {
                if seen.insert(dedup_key(&server)) {
                    out.servers.push(*server);
                } else {
                    out.duplicates += 1;
                }
            }
            Ok(Entry::Info(text)) => out.info.push(text),
            Err(e) => out.errors.push((idx + 1, e)),
        }
    }
    out
}

fn dedup_key(s: &Server) -> String {
    // В ключ входит сериализованная модель целиком: два сервера с одним адресом,
    // но разными транспортами — разные варианты, и оба нужны адаптивному выбору.
    serde_json::to_string(s).unwrap_or_default()
}

fn is_info_entry(s: &Server) -> bool {
    let addr = s.address.trim_matches(['[', ']']);
    matches!(addr, "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "localhost") || s.port <= 1
}

/// base64 в любом из четырёх распространённых вариантов, пробелы и переводы строк игнорируются.
pub(crate) fn decode_base64_lenient(input: &str) -> Option<Vec<u8>> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())
}

pub(crate) fn decode_component(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

pub(crate) fn parse_url(input: &str) -> Result<Url, ParseError> {
    Url::parse(input).map_err(|_| ParseError::InvalidUrl)
}

/// Хост без квадратных скобок IPv6.
pub(crate) fn host_of(url: &Url) -> Result<String, ParseError> {
    let host = url.host_str().ok_or(ParseError::MissingField("адрес"))?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(ParseError::MissingField("адрес"));
    }
    Ok(host.to_owned())
}

pub(crate) fn port_of(url: &Url) -> Result<u16, ParseError> {
    match url.port() {
        Some(0) => Err(ParseError::InvalidField {
            field: "порт",
            reason: "равен нулю",
        }),
        Some(p) => Ok(p),
        None => Err(ParseError::MissingField("порт")),
    }
}

pub(crate) fn name_of(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(decode_component)
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

/// Параметры запроса: ключи без учёта регистра, при повторе берётся первое значение.
pub(crate) fn query_of(url: &Url) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in url.query_pairs() {
        map.entry(k.to_ascii_lowercase())
            .or_insert_with(|| v.into_owned());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLESS_REALITY: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?type=tcp&security=reality&sni=www.microsoft.com&fp=firefox&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B";

    #[test]
    fn plain_and_base64_bodies_give_same_result() {
        let body = format!("{VLESS_REALITY}\ntrojan://pass@example.com:443?sni=example.com#T");
        let b64 = STANDARD.encode(&body);
        let a = parse_subscription_body(&body);
        let b = parse_subscription_body(&b64);
        assert_eq!(a.servers, b.servers);
        assert_eq!(a.servers.len(), 2);
        assert!(a.errors.is_empty());
    }

    #[test]
    fn info_entries_are_not_servers() {
        let body = "trojan://x@0.0.0.0:1#%D0%9E%D1%81%D1%82%D0%B0%D0%BB%D0%BE%D1%81%D1%8C%2010%20%D0%93%D0%91";
        let c = parse_subscription_body(body);
        assert!(c.servers.is_empty());
        assert_eq!(c.info, vec!["Осталось 10 ГБ".to_owned()]);
    }

    #[test]
    fn duplicates_are_dropped() {
        let body = format!("{VLESS_REALITY}\n{VLESS_REALITY}");
        let c = parse_subscription_body(&body);
        assert_eq!(c.servers.len(), 1);
        assert_eq!(c.duplicates, 1);
    }

    #[test]
    fn errors_do_not_leak_secrets() {
        let bad = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@host:443?security=reality&sni=a.com&pbk=short";
        let err = parse_uri(bad).unwrap_err();
        let text = err.to_string();
        assert!(!text.contains("b831381d"));
        assert!(!text.contains("short"));
    }

    #[test]
    fn unknown_scheme_is_truncated() {
        let err = parse_uri("averyveryveryverylongscheme://x").unwrap_err();
        assert_eq!(err, ParseError::UnknownScheme("averyveryveryver".into()));
    }

    #[test]
    fn json_subscription_is_reported_unsupported() {
        let c = parse_subscription_body("{\"outbounds\": []}");
        assert!(matches!(
            c.errors.as_slice(),
            [(0, ParseError::Unsupported(_))]
        ));
    }

    proptest::proptest! {
        #[test]
        fn parser_never_panics(s in "\\PC{0,512}") {
            let _ = parse_uri(&s);
            let _ = parse_subscription_body(&s);
        }

        #[test]
        fn parser_never_panics_on_vless_like(s in "vless://[a-z0-9@:.?=&#%-]{0,200}") {
            let _ = parse_uri(&s);
        }
    }
}
