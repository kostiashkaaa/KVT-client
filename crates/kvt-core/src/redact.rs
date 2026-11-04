//! Маскировщик для журналов и экспорта диагностики: всё, что пишется на диск или
//! уходит из KVT, проходит через [`text`].
//!
//! Что скрывается:
//! - адреса VPN-серверов — их заранее передают в [`set_servers`] (до запуска ядра),
//!   а не ищут в тексте по догадке;
//! - ссылки: у `http(s)://` остаётся только хост, ссылки на серверы
//!   (`vless://`, `ss://`…) скрываются целиком;
//! - UUID (идентификаторы пользователей VLESS / VMess);
//! - длинные токены: ключи REALITY, пароли, хэши в ссылках подписок.
//!
//! Для JSON-конфигов ядер есть [`json`]: поля с секретами скрываются по имени.

use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Чем заменяется адрес сервера.
pub const SERVER: &str = "[сервер]";
/// Чем заменяется секрет.
pub const HIDDEN: &str = "***";
/// Токен такой длины и длиннее считается секретом.
const TOKEN_LEN: usize = 32;

type Servers = HashSet<String>;

/// Адреса в нижнем регистре. Множество, а не список: подписок с тысячами
/// серверов много, а маскируется каждая строка журнала.
static SERVERS: Mutex<Option<Arc<Servers>>> = Mutex::new(None);

fn normalize(a: &str) -> String {
    a.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Адреса серверов, которые надо скрывать (заменяет прежний набор).
pub fn set_servers<I, S>(addresses: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let set: Servers = addresses
        .into_iter()
        .map(|a| normalize(a.as_ref()))
        // Слишком короткое «имя» (`a`, `1`) заменило бы половину текста.
        .filter(|a| a.len() >= 4)
        .collect();
    if let Ok(mut s) = SERVERS.lock() {
        *s = Some(Arc::new(set));
    }
}

/// Добавляет адреса к уже известным (служба узнаёт ещё и IP, в которые
/// разрешилось имя сервера).
pub fn add_servers<I, S>(addresses: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut set: Servers = current().as_ref().clone();
    set.extend(
        addresses
            .into_iter()
            .map(|a| normalize(a.as_ref()))
            .filter(|a| a.len() >= 4),
    );
    if let Ok(mut s) = SERVERS.lock() {
        *s = Some(Arc::new(set));
    }
}

fn current() -> Arc<Servers> {
    SERVERS
        .lock()
        .ok()
        .and_then(|s| s.clone())
        .unwrap_or_default()
}

/// Текст без секретов и адресов серверов.
pub fn text(s: &str) -> String {
    text_with(s, &current())
}

fn text_with(s: &str, servers: &Servers) -> String {
    let s = links(s);
    let s = hide_servers(&s, servers);
    let s = uuids(&s);
    tokens(&s)
}

fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.')
}

/// Ссылки: у веб-ссылок остаётся схема и хост, ссылки на серверы скрываются целиком.
fn links(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("://") {
        let before = &rest[..pos];
        let scheme_start = before
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
            .last()
            .map_or(pos, |(i, _)| i);
        let scheme = before[scheme_start..].to_ascii_lowercase();
        let after = &rest[pos + 3..];
        let end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '|' | '`'))
            .unwrap_or(after.len());
        // Знаки препинания в конце принадлежат предложению, а не ссылке.
        let link = after[..end].trim_end_matches(['.', ',', ';', ':', ')', ']', '}']);
        out.push_str(&rest[..scheme_start]);
        if scheme.is_empty() {
            out.push_str("://");
            rest = after;
            continue;
        }
        out.push_str(&scheme);
        out.push_str("://");
        if matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
            out.push_str(&crate::netlog::host_of(&format!("{scheme}://{link}")));
            // Путь и параметры (в них токены подписок) — многоточием.
            if link.contains(['/', '?', '#']) {
                out.push_str("/…");
            }
        } else {
            out.push_str(HIDDEN);
        }
        rest = &after[link.len()..];
    }
    out.push_str(rest);
    out
}

/// Адреса серверов — на [`SERVER`], только целыми словами: текст режется на
/// слова из букв, цифр, точек и дефисов, и слово сверяется с множеством. Так
/// `1.2.3.4` не заденет `11.2.3.45`, а `vpn.example.com` — `myvpn.example.com.evil`.
fn hide_servers(s: &str, servers: &Servers) -> String {
    if servers.is_empty() {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut word_start: Option<usize> = None;
    let flush = |out: &mut String, word: &str| {
        // Точка в конце слова — конец предложения, а не часть имени.
        let core = word.trim_end_matches('.');
        if core.len() >= 4 && servers.contains(&core.to_ascii_lowercase()) {
            out.push_str(SERVER);
            out.push_str(&word[core.len()..]);
        } else {
            out.push_str(word);
        }
    };
    for (i, c) in s.char_indices() {
        match (is_host_char(c), word_start) {
            (true, None) => word_start = Some(i),
            (false, Some(st)) => {
                flush(&mut out, &s[st..i]);
                word_start = None;
                out.push(c);
            }
            (false, None) => out.push(c),
            (true, Some(_)) => {}
        }
    }
    if let Some(st) = word_start {
        flush(&mut out, &s[st..]);
    }
    out
}

/// UUID вида `b831381d-6324-4d53-ad4f-8cda48b30811`.
pub fn uuids(line: &str) -> String {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    'outer: while i < bytes.len() {
        if i + 36 <= bytes.len() {
            let mut pos = i;
            let mut ok = true;
            for (g, len) in GROUPS.iter().enumerate() {
                if !bytes[pos..pos + len].iter().all(u8::is_ascii_hexdigit) {
                    ok = false;
                    break;
                }
                pos += len;
                if g < 4 {
                    if bytes[pos] != b'-' {
                        ok = false;
                        break;
                    }
                    pos += 1;
                }
            }
            if ok {
                out.push_str("********-****-****-****-************");
                i += 36;
                continue 'outer;
            }
        }
        let ch = line[i..].chars().next().unwrap_or('?');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Длинные последовательности из букв и цифр (base64, hex) — ключи и пароли.
fn tokens(s: &str) -> String {
    let is_tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '/' | '=' | '-');
    let mut out = String::with_capacity(s.len());
    let mut start: Option<usize> = None;
    let flush = |out: &mut String, word: &str| {
        let has_digit = word.chars().any(|c| c.is_ascii_digit());
        let has_alpha = word.chars().any(|c| c.is_ascii_alphabetic());
        // Пути вида `a/b/c` из коротких частей — не токен.
        let longest_part = word.split('/').map(str::len).max().unwrap_or(0);
        if word.len() >= TOKEN_LEN && has_digit && has_alpha && longest_part >= TOKEN_LEN {
            out.push_str(HIDDEN);
        } else {
            out.push_str(word);
        }
    };
    for (i, c) in s.char_indices() {
        match (is_tok(c), start) {
            (true, None) => start = Some(i),
            (false, Some(st)) => {
                flush(&mut out, &s[st..i]);
                start = None;
                out.push(c);
            }
            (false, None) => out.push(c),
            (true, Some(_)) => {}
        }
    }
    if let Some(st) = start {
        flush(&mut out, &s[st..]);
    }
    out
}

/// Поля конфигов ядер, где лежат секреты.
const SECRET_KEYS: &[&str] = &[
    "id",
    "uuid",
    "password",
    "pass",
    "auth",
    "auth_str",
    "obfs_password",
    "publickey",
    "public_key",
    "privatekey",
    "private_key",
    "shortid",
    "short_id",
    "psk",
    "pre_shared_key",
    "pinsha256",
    "certificate_public_key_sha256",
    "user",
    "username",
];

/// Поля с адресом сервера.
const ADDRESS_KEYS: &[&str] = &["address", "server"];

/// JSON-конфиг ядра без секретов: значения секретных полей — [`HIDDEN`], адреса
/// серверов — [`SERVER`], остальные строки — через [`text`].
pub fn json(value: &Value) -> Value {
    json_with(value, &current())
}

fn json_with(value: &Value, servers: &Servers) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let key = k.to_ascii_lowercase();
                    let v = if SECRET_KEYS.contains(&key.as_str()) && !v.is_object() {
                        Value::String(HIDDEN.into())
                    } else if ADDRESS_KEYS.contains(&key.as_str()) && v.is_string() {
                        let s = v.as_str().unwrap_or_default();
                        if servers.contains(&normalize(s)) {
                            Value::String(SERVER.into())
                        } else {
                            Value::String(text_with(s, servers))
                        }
                    } else {
                        json_with(v, servers)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| json_with(v, servers)).collect()),
        Value::String(s) => Value::String(text_with(s, servers)),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn servers() -> Servers {
        ["vpn.example.com", "203.0.113.10"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn none() -> Servers {
        Servers::new()
    }

    #[test]
    fn web_links_keep_only_host() {
        assert_eq!(
            text_with(
                "загрузка https://sub.example.com/SECRET-TOKEN?x=1 не удалась.",
                &none()
            ),
            "загрузка https://sub.example.com/… не удалась."
        );
        assert_eq!(
            text_with("см. https://user:pw@github.com/a/b", &none()),
            "см. https://github.com/…"
        );
        assert_eq!(
            text_with("сайт http://ya.ru, всё", &none()),
            "сайт http://ya.ru, всё"
        );
    }

    #[test]
    fn server_links_are_hidden_entirely() {
        assert_eq!(
            text_with("ключ vless://uuid@1.2.3.4:443?pbk=x#NL и всё", &none()),
            "ключ vless://*** и всё"
        );
        assert_eq!(text_with("ss://YWVzOnB3@h:1", &none()), "ss://***");
    }

    #[test]
    fn server_addresses_by_whole_word() {
        let s = servers();
        assert_eq!(
            text_with("dial tcp 203.0.113.10:443: i/o timeout", &s),
            "dial tcp [сервер]:443: i/o timeout"
        );
        assert_eq!(
            text_with("dial 203.0.113.100:443", &s),
            "dial 203.0.113.100:443"
        );
        assert_eq!(
            text_with("VPN.Example.com не отвечает.", &s),
            "[сервер] не отвечает."
        );
        assert_eq!(
            text_with("myvpn.example.com.evil", &s),
            "myvpn.example.com.evil"
        );
    }

    #[test]
    fn uuids_and_tokens() {
        assert_eq!(
            text_with(
                "user b831381d-6324-4d53-ad4f-8cda48b30811 отвергнут",
                &none()
            ),
            "user ********-****-****-****-************ отвергнут"
        );
        assert_eq!(
            text_with(
                "pbk Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw неверен",
                &none()
            ),
            "pbk *** неверен"
        );
        // Обычные слова и пути не трогаются.
        assert_eq!(
            text_with(
                r"C:\ProgramData\KVT\rules\geosite-category-ads-all.srs",
                &none()
            ),
            r"C:\ProgramData\KVT\rules\geosite-category-ads-all.srs"
        );
        assert_eq!(text_with("обычная строка", &none()), "обычная строка");
    }

    #[test]
    fn json_configs_hide_secrets_and_servers() {
        let config = json!({
            "outbounds": [{
                "type": "vless",
                "server": "vpn.example.com",
                "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "tls": { "reality": { "public_key": "abc", "short_id": "01" }, "server_name": "a.com" }
            }],
            "dns": { "servers": [{ "server": "1.1.1.1" }] }
        });
        let out = json_with(&config, &servers());
        let ob = &out["outbounds"][0];
        assert_eq!(ob["server"], SERVER);
        assert_eq!(ob["uuid"], HIDDEN);
        assert_eq!(ob["server_port"], 443);
        assert_eq!(ob["tls"]["reality"]["public_key"], HIDDEN);
        assert_eq!(ob["tls"]["reality"]["short_id"], HIDDEN);
        assert_eq!(ob["tls"]["server_name"], "a.com");
        assert_eq!(out["dns"]["servers"][0]["server"], "1.1.1.1");
    }

    #[test]
    fn short_names_are_not_registered() {
        set_servers(["a", "vpn.example.com"]);
        assert_eq!(text("a b vpn.example.com"), "a b [сервер]");
        set_servers(Vec::<String>::new());
    }
}
