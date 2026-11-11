//! Разбор ссылок и тел подписок. Вход недоверенный: никаких паник, лимиты на
//! размер, ошибки не содержат секретов из исходной строки.

mod anytls;
mod http;
mod hysteria2;
mod shadowsocks;
mod sing_box_json;
mod socks;
mod stream;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod xhttp_extra;
mod xray_json;

pub use http::is_proxy_link as is_http_proxy_link;

use crate::model::Server;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use url::Url;

/// Больше строк в подписке не разбираем — защита от «бомб».
pub const MAX_SUBSCRIPTION_LINES: usize = 10_000;
/// Максимальная длина одной ссылки.
pub const MAX_URI_LEN: usize = 8 * 1024;
/// Разделитель вставок в группе «Добавлено вручную» (ASCII Record Separator, в
/// подписках не встречается). Каждая вставка разбирается сама по себе: base64,
/// конфиги Xray в JSON и ссылки нельзя склеить в один текст — после склейки base64
/// перестаёт декодироваться, а JSON — разбираться.
pub const CHUNK_SEPARATOR: char = '\u{1e}';

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("{}", crate::trf!("неизвестная схема ссылки «{}»", "unknown link scheme “{}”", .0))]
    UnknownScheme(String),
    #[error("{}", crate::i18n::tr("ссылка повреждена", "broken link"))]
    InvalidUrl,
    #[error("{}", crate::i18n::tr("ссылка слишком длинная", "link is too long"))]
    TooLong,
    #[error("{}", crate::trf!("не хватает поля «{}»", "missing field “{}”", .0))]
    MissingField(&'static str),
    #[error("{}", crate::trf!("некорректное поле «{}»: {}", "invalid field “{}”: {}", .field, .reason))]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{}", crate::trf!("не поддерживается: {}", "not supported: {}", .0))]
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
        "vmess" => vmess::parse(input)?,
        "tuic" => tuic::parse(input)?,
        "anytls" => anytls::parse(input)?,
        "socks" | "socks5" | "socks5h" | "socks4" | "socks4a" => socks::parse(input)?,
        // Только ссылки вида прокси (логин и пустой путь); сайт или подписка — ошибка
        // «неизвестная схема», как раньше.
        "http" | "https" => http::parse(input)?,
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

/// Разбирает тело подписки: список ссылок, в том числе в base64, или конфиги Xray.
/// Тело из нескольких вставок (`CHUNK_SEPARATOR`) разбирается по кускам.
pub fn parse_subscription_body(body: &str) -> SubscriptionContent {
    let mut out = SubscriptionContent::default();
    let mut seen = HashSet::new();
    let mut offset = 0;
    for chunk in body.split(CHUNK_SEPARATOR) {
        offset += parse_chunk(&mut out, &mut seen, chunk, offset);
    }
    out
}

/// Одна вставка. `offset` — сколько строк было в предыдущих вставках (для номеров
/// строк в ошибках). Возвращает число строк этой вставки.
fn parse_chunk(
    out: &mut SubscriptionContent,
    seen: &mut HashSet<String>,
    chunk: &str,
    offset: usize,
) -> usize {
    // BOM в начале (текст из Блокнота) — не часть base64 и не часть ссылки.
    let trimmed = chunk.trim().trim_start_matches('\u{feff}').trim_start();

    let decoded;
    let text = if trimmed.contains("://") {
        trimmed
    } else if let Some(bytes) = decode_base64_lenient(trimmed) {
        decoded = String::from_utf8_lossy(&bytes).into_owned();
        decoded.as_str()
    } else {
        trimmed
    };

    let is_json = text.starts_with('{') || text.starts_with('[');
    // Конфиги sing-box и Xray: номер «строки» в ошибках — номер подключения или
    // конфига в массиве. sing-box первым: у его конфига тоже есть `outbounds`.
    let entries = is_json
        .then(|| sing_box_json::parse(text).or_else(|| xray_json::parse(text)))
        .flatten();
    if let Some(entries) = entries {
        let count = entries.len();
        for (idx, entry) in entries.into_iter().enumerate() {
            add_entry(out, seen, offset + idx + 1, entry);
        }
        return count;
    }
    if is_json {
        out.errors.push((
            offset,
            ParseError::Unsupported(crate::i18n::tr(
                "JSON без списка подключений (outbounds)",
                "JSON without a list of connections (outbounds)",
            )),
        ));
        return 1;
    }
    if text.starts_with("proxies:") || text.contains("\nproxies:") {
        out.errors.push((
            offset,
            ParseError::Unsupported(crate::i18n::tr(
                "подписки Clash пока не поддерживаются",
                "Clash subscriptions aren't supported yet",
            )),
        ));
        return 1;
    }

    let budget = MAX_SUBSCRIPTION_LINES.saturating_sub(offset);
    let mut count = 0;
    for (idx, line) in text.lines().enumerate().take(budget) {
        count = idx + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || !line.contains("://") {
            continue;
        }
        add_entry(out, seen, offset + idx + 1, parse_uri(line));
    }
    count
}

/// Вставка для группы «Добавлено вручную» в виде ссылок, по одной на строку:
/// base64 раскрывается, конфиги Xray в JSON переводятся в ссылки. В группе остаются
/// только ссылки — тогда один сервер удаляется вместе со своей строкой.
/// Нераспознанное (например, Clash) остаётся как есть: разбор покажет ошибку.
pub fn normalize_pasted(body: &str) -> String {
    let trimmed = body.trim().trim_start_matches('\u{feff}').trim_start();
    let decoded;
    let text = if trimmed.contains("://") {
        trimmed
    } else if let Some(bytes) = decode_base64_lenient(trimmed) {
        decoded = String::from_utf8_lossy(&bytes).into_owned();
        decoded.trim()
    } else {
        trimmed
    };
    if text.starts_with('{') || text.starts_with('[') {
        if let Some(links) = sing_box_json::links(text).or_else(|| xray_json::links(text)) {
            // Конфиг без поддерживаемого подключения пропускается — как и при разборе.
            return links.into_iter().flatten().collect::<Vec<_>>().join("\n");
        }
    }
    text.to_owned()
}

/// Убирает из тела группы «Добавлено вручную» строки сервера `target` (и его
/// точные повторы). `None` — строки этого сервера в теле нет (например, он из
/// нераспознанного куска). Пустые куски выбрасываются.
pub fn remove_server(body: &str, target: &Server) -> Option<String> {
    edit_server_lines(body, target, None)
}

/// Заменяет в теле группы «Добавлено вручную» строку сервера `target` на `line`
/// (точные повторы убираются). `None` — строки этого сервера в теле нет.
pub fn replace_server(body: &str, target: &Server, line: &str) -> Option<String> {
    edit_server_lines(body, target, Some(line))
}

fn edit_server_lines(body: &str, target: &Server, replacement: Option<&str>) -> Option<String> {
    let mut found = false;
    let chunks: Vec<String> = body
        .split(CHUNK_SEPARATOR)
        .map(|chunk| {
            normalize_pasted(chunk)
                .lines()
                .filter_map(|line| {
                    if !matches!(parse_uri(line), Ok(Entry::Server(s)) if *s == *target) {
                        return Some(line.to_owned());
                    }
                    // Первое вхождение заменяется, повторы выбрасываются.
                    let first = !found;
                    found = true;
                    replacement.filter(|_| first).map(str::to_owned)
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|chunk| !chunk.trim().is_empty())
        .collect();
    found.then(|| chunks.join(&format!("\n{CHUNK_SEPARATOR}\n")))
}

/// Самое длинное название сервера, которое можно задать вручную.
pub const MAX_NAME_CHARS: usize = 120;

/// Ссылка на сервер с другим названием (фрагмент `#…`). Остальное не меняется.
pub fn with_name(line: &str, name: &str) -> Result<String, ParseError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ParseError::MissingField(crate::i18n::tr(
            "название",
            "name",
        )));
    }
    if name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(ParseError::InvalidField {
            field: crate::i18n::tr("название", "name"),
            reason: crate::i18n::tr(
                "слишком длинное или с непечатаемыми символами",
                "too long or has non-printable characters",
            ),
        });
    }
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    let base = line.trim().split('#').next().unwrap_or_default();
    let renamed = format!(
        "{base}#{}",
        percent_encoding::utf8_percent_encode(name, SET)
    );
    // Проверка: ссылка по-прежнему разбирается, и название то, что задали.
    match parse_uri(&renamed)? {
        Entry::Server(s) if s.name == name => Ok(renamed),
        _ => Err(ParseError::InvalidUrl),
    }
}

fn add_entry(
    out: &mut SubscriptionContent,
    seen: &mut HashSet<String>,
    line: usize,
    entry: Result<Entry, ParseError>,
) {
    match entry {
        Ok(Entry::Server(server)) => {
            if seen.insert(dedup_key(&server)) {
                out.servers.push(*server);
            } else {
                out.duplicates += 1;
            }
        }
        Ok(Entry::Info(text)) => out.info.push(text),
        Err(e) => out.errors.push((line, e)),
    }
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

/// `extra` XHTTP после белого списка (`None` — ничего не осталось или он испорчен).
/// Компилятор берёт его отсюда, а не как есть: модель могла прийти не из парсера.
pub(crate) fn sanitized_extra(extra: &str) -> Option<String> {
    xhttp_extra::sanitize(extra).ok().flatten()
}

/// Проверка сервера, который пришёл не из парсера: служба получает его по IPC от
/// окна и окну не доверяет — из этих полей она соберёт конфиг ядра, которое
/// работает от SYSTEM. Те же ограничения, что при разборе: адрес — имя хоста или
/// IP, строки без управляющих символов, `extra`, фрагментация и порты — по белому
/// списку. Ошибка не содержит значений полей.
pub fn check_server(s: &Server) -> Result<(), ParseError> {
    use crate::model::{Protocol, Security, Transport};
    let invalid = |field: &'static str| ParseError::InvalidField {
        field,
        reason: crate::i18n::tr("недопустимое значение", "invalid value"),
    };

    fn add<'a>(
        texts: &mut Vec<(&'static str, &'a str)>,
        field: &'static str,
        value: Option<&'a str>,
    ) {
        if let Some(v) = value {
            texts.push((field, v));
        }
    }
    let mut texts: Vec<(&'static str, &str)> = vec![("address", s.address.as_str())];
    match &s.protocol {
        Protocol::Vless { id, encryption, .. } => {
            add(&mut texts, "id", Some(id.expose()));
            add(&mut texts, "encryption", encryption.as_deref());
        }
        Protocol::Trojan { password } | Protocol::AnyTls { password } => {
            add(&mut texts, "password", Some(password.expose()));
        }
        Protocol::Shadowsocks { method, password } => {
            add(&mut texts, "method", Some(method.as_str()));
            add(&mut texts, "password", Some(password.expose()));
        }
        Protocol::Hysteria2 {
            password,
            obfs,
            ports,
            pin_sha256,
        } => {
            add(&mut texts, "password", Some(password.expose()));
            if let Some(o) = obfs {
                add(&mut texts, "obfs", Some(o.kind.as_str()));
                add(&mut texts, "obfs-password", Some(o.password.expose()));
            }
            add(&mut texts, "pinSHA256", pin_sha256.as_deref());
            if let Some(p) = ports {
                if hysteria2::normalize_ranges(p).as_deref() != Ok(p.as_str()) {
                    return Err(invalid("ports"));
                }
            }
        }
        Protocol::Vmess { id, cipher } => {
            add(&mut texts, "id", Some(id.expose()));
            add(&mut texts, "cipher", Some(cipher.as_str()));
        }
        Protocol::Tuic {
            uuid,
            password,
            congestion,
            udp_relay_mode,
        } => {
            add(&mut texts, "uuid", Some(uuid.expose()));
            add(&mut texts, "password", Some(password.expose()));
            add(&mut texts, "congestion", congestion.as_deref());
            add(&mut texts, "udp_relay_mode", udp_relay_mode.as_deref());
        }
        Protocol::Socks { username, password } | Protocol::Http { username, password } => {
            add(
                &mut texts,
                "username",
                username.as_ref().map(crate::Secret::expose),
            );
            add(
                &mut texts,
                "password",
                password.as_ref().map(crate::Secret::expose),
            );
        }
    }
    match &s.transport {
        Transport::Tcp | Transport::Quic => {}
        Transport::Ws { path, host } | Transport::HttpUpgrade { path, host } => {
            add(&mut texts, "path", Some(path.as_str()));
            add(&mut texts, "host", host.as_deref());
        }
        Transport::Grpc { service_name } => {
            add(&mut texts, "serviceName", Some(service_name.as_str()))
        }
        Transport::Xhttp {
            path,
            host,
            mode,
            extra,
        } => {
            add(&mut texts, "path", Some(path.as_str()));
            add(&mut texts, "host", host.as_deref());
            add(&mut texts, "mode", mode.as_deref());
            if let Some(e) = extra {
                if e.len() > MAX_URI_LEN || sanitized_extra(e).is_none() {
                    return Err(invalid("extra"));
                }
            }
        }
    }
    match &s.security {
        Security::None => {}
        Security::Tls(t) => {
            add(&mut texts, "sni", t.sni.as_deref());
            add(&mut texts, "ech", t.ech.as_deref());
            for a in &t.alpn {
                add(&mut texts, "alpn", Some(a.as_str()));
            }
        }
        Security::Reality(r) => {
            add(&mut texts, "sni", Some(r.sni.as_str()));
            add(&mut texts, "pbk", Some(r.public_key.as_str()));
            add(&mut texts, "sid", Some(r.short_id.as_str()));
            add(&mut texts, "spx", r.spider_x.as_deref());
        }
    }
    if let Some((field, _)) = texts
        .iter()
        .find(|(_, v)| v.len() > MAX_URI_LEN || v.chars().any(char::is_control))
    {
        return Err(invalid(field));
    }

    let address = s.address.trim_matches(['[', ']']);
    let host_ok = address.parse::<std::net::IpAddr>().is_ok()
        || matches!(url::Host::parse(address), Ok(url::Host::Domain(_)));
    if !host_ok {
        return Err(invalid("address"));
    }
    if s.port == 0 {
        return Err(invalid("port"));
    }
    if let Some(f) = &s.fragment {
        stream::fragment_from(&f.packets, &f.length, &f.delay)?;
    }
    if s.mux.is_some_and(|n| !(1..=1024).contains(&n)) {
        return Err(invalid("mux"));
    }
    Ok(())
}

pub(crate) fn parse_url(input: &str) -> Result<Url, ParseError> {
    Url::parse(input).map_err(|_| ParseError::InvalidUrl)
}

/// Хост без квадратных скобок IPv6.
pub(crate) fn host_of(url: &Url) -> Result<String, ParseError> {
    let host = url
        .host_str()
        .ok_or(ParseError::MissingField(crate::i18n::tr(
            "адрес",
            "address",
        )))?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(ParseError::MissingField(crate::i18n::tr(
            "адрес",
            "address",
        )));
    }
    Ok(host.to_owned())
}

pub(crate) fn port_of(url: &Url) -> Result<u16, ParseError> {
    match url.port() {
        Some(0) => Err(ParseError::InvalidField {
            field: crate::i18n::tr("порт", "port"),
            reason: crate::i18n::tr("равен нулю", "is zero"),
        }),
        Some(p) => Ok(p),
        None => Err(ParseError::MissingField(crate::i18n::tr("порт", "port"))),
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

    fn parsed(uri: &str) -> Server {
        match parse_uri(uri).unwrap() {
            Entry::Server(s) => *s,
            Entry::Info(_) => panic!("ожидался сервер: {uri}"),
        }
    }

    const XHTTP: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@up.example.com:443?type=xhttp&security=tls&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&fragment=tlshello,100-200,10-20#x";

    #[test]
    fn parsed_servers_pass_the_service_check() {
        for uri in [
            VLESS_REALITY,
            XHTTP,
            "trojan://pass@example.com:443?type=ws&path=%2Fws&host=example.com&sni=example.com#T",
            "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@198.51.100.7:8388#ss",
            "hy2://secret@hy.example.com:8443?obfs=salamander&obfs-password=x&sni=hy.example.com#hy2",
            "hy2://secret@hy.example.com:443,20000-30000?sni=hy.example.com#hop",
            "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MiLCJhZGQiOiJ2bS5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJwYXRoIjoiL3ZtIiwiaG9zdCI6InZtLmV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwic25pIjoidm0uZXhhbXBsZS5jb20ifQ==",
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@tu.example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=tu.example.com#tuic",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443?security=tls&sni=v6.example.com#v6",
        ] {
            let s = parsed(uri);
            assert_eq!(check_server(&s), Ok(()), "{uri}");
        }
    }

    /// Служба получает модель по IPC, минуя парсер: всё, что парсер не пропустил бы,
    /// отвергается — в первую очередь `extra` с путями к файлам для ядра от SYSTEM.
    #[test]
    fn forged_server_is_rejected() {
        use crate::model::Transport;
        let base = parsed(XHTTP);
        let with_extra = |extra: &str| {
            let mut s = base.clone();
            if let Transport::Xhttp { extra: e, .. } = &mut s.transport {
                *e = Some(extra.to_owned());
            }
            s
        };
        // Путь к файлу в `downloadSettings` пропадает при повторном белом списке,
        // поэтому ядро его не увидит; а непарсящийся `extra` — ошибка.
        let evil = r#"{"downloadSettings":{"address":"dl.example.com","port":443,"security":"tls","tlsSettings":{"masterKeyLog":"C:\\Windows\\x.dll"}}}"#;
        let s = with_extra(evil);
        assert_eq!(check_server(&s), Ok(()));
        let clean = sanitized_extra(evil).unwrap();
        assert!(!clean.contains("masterKeyLog"), "{clean}");
        assert!(check_server(&with_extra("not json")).is_err());
        assert!(check_server(&with_extra(r#"{"downloadSettings":{"port":1}}"#)).is_err());

        let mut s = base.clone();
        s.address = "evil host/../x".into();
        assert!(check_server(&s).is_err());
        let mut s = base.clone();
        s.address = String::new();
        assert!(check_server(&s).is_err());
        let mut s = base.clone();
        if let Transport::Xhttp { path, .. } = &mut s.transport {
            *path = "/x\n--evil".into();
        }
        assert!(check_server(&s).is_err());
        let mut s = base.clone();
        s.fragment.as_mut().unwrap().delay = "999999".into();
        assert!(check_server(&s).is_err());
        let mut s = base.clone();
        s.mux = Some(0);
        assert!(check_server(&s).is_err());

        let mut s = parsed("hy2://secret@hy.example.com:443,20000-30000?sni=hy.example.com#hop");
        if let crate::model::Protocol::Hysteria2 { ports, .. } = &mut s.protocol {
            *ports = Some("1-2,evil".into());
        }
        assert!(check_server(&s).is_err());
    }

    #[test]
    fn errors_in_english() {
        use crate::i18n::{with, Lang};
        let e = with(Lang::En, || parse_uri("foo://x").unwrap_err().to_string());
        assert_eq!(e, "unknown link scheme “foo”");
        let e = with(Lang::Ru, || parse_uri("foo://x").unwrap_err().to_string());
        assert_eq!(e, "неизвестная схема ссылки «foo»");
    }

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

    /// Ручная группа: base64 и ссылки вставлены в разное время — видны все серверы.
    #[test]
    fn base64_and_links_pasted_separately() {
        let link = "trojan://pass@example.com:443?sni=example.com#T";
        let b64 = STANDARD.encode(VLESS_REALITY);
        for body in [
            format!("{b64}\n{CHUNK_SEPARATOR}\n{link}"),
            format!("{link}\n{CHUNK_SEPARATOR}\n{b64}"),
        ] {
            let c = parse_subscription_body(&body);
            assert_eq!(c.servers.len(), 2, "{body}");
            assert!(c.errors.is_empty());
        }
        // Одинаковый сервер в двух вставках — один.
        let twice = format!("{VLESS_REALITY}\n{CHUNK_SEPARATOR}\n{b64}");
        assert_eq!(parse_subscription_body(&twice).servers.len(), 1);
    }

    #[test]
    fn rename_keeps_everything_but_the_name() {
        let renamed = with_name(VLESS_REALITY, "🇳🇱 Дом #2").unwrap();
        let Entry::Server(old) = parse_uri(VLESS_REALITY).unwrap() else {
            panic!()
        };
        let Entry::Server(new) = parse_uri(&renamed).unwrap() else {
            panic!()
        };
        assert_eq!(new.name, "🇳🇱 Дом #2");
        let mut same = *new.clone();
        same.name = old.name.clone();
        assert_eq!(same, *old);

        let ss = "ss://YWVzLTI1Ni1nY206cGFzcw@198.51.100.7:8388#Old";
        let Entry::Server(s) = parse_uri(&with_name(ss, "Новый").unwrap()).unwrap() else {
            panic!()
        };
        assert_eq!(s.name, "Новый");

        assert!(with_name(VLESS_REALITY, "  ").is_err());
        assert!(with_name(VLESS_REALITY, "a\nb").is_err());
        assert!(with_name(VLESS_REALITY, &"x".repeat(MAX_NAME_CHARS + 1)).is_err());
    }

    #[test]
    fn replace_server_swaps_one_line() {
        let trojan = "trojan://pass@example.com:443?sni=example.com#T";
        let body = format!("{VLESS_REALITY}\n{CHUNK_SEPARATOR}\n{trojan}\n{VLESS_REALITY}");
        let Entry::Server(target) = parse_uri(VLESS_REALITY).unwrap() else {
            panic!()
        };
        let other = "trojan://pass@other.example.com:443?sni=other.example.com#O";
        let new = replace_server(&body, &target, other).unwrap();
        let names: Vec<String> = parse_subscription_body(&new)
            .servers
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["O", "T"]);
        assert!(replace_server(&new, &target, other).is_none());
    }

    #[test]
    fn bom_before_base64_is_ignored() {
        let body = format!("\u{feff}{}", STANDARD.encode(VLESS_REALITY));
        assert_eq!(parse_subscription_body(&body).servers.len(), 1);
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
        let c = parse_subscription_body("{\"proxies\": []}");
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
