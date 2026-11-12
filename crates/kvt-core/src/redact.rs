//! Маскировщик для журналов и экспорта диагностики: всё, что пишется на диск или
//! уходит из KVT, проходит через [`text`].
//!
//! Что скрывается:
//! - адреса VPN-серверов — их заранее передают в [`set_servers`] (до запуска ядра),
//!   а не ищут в тексте по догадке; IPv6 — в любой записи;
//! - пароли и идентификаторы серверов — из [`set_secrets`]: короткий пароль на токен
//!   не похож;
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
type Secrets = HashSet<String>;

/// Секрет короче — не скрывается: такая строка встречается в журнале и так.
const SECRET_MIN: usize = 6;

/// Адреса в нижнем регистре. Множество, а не список: подписок с тысячами
/// серверов много, а маскируется каждая строка журнала.
static SERVERS: Mutex<Option<Arc<Servers>>> = Mutex::new(None);
static SECRETS: Mutex<Option<Arc<Secrets>>> = Mutex::new(None);

/// Адрес для сравнения: нижний регистр, IPv6 — в одной записи (`2001:DB8:0::1` и
/// `2001:db8::1` — один адрес).
fn normalize(a: &str) -> String {
    let a = a
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    match a.parse::<std::net::Ipv6Addr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => a,
    }
}

/// Пароли и идентификаторы, которые надо скрывать (заменяет прежний набор).
pub fn set_secrets<I, S>(secrets: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let set: Secrets = secrets
        .into_iter()
        .map(|s| s.as_ref().to_owned())
        .filter(|s| s.chars().count() >= SECRET_MIN)
        .collect();
    if let Ok(mut s) = SECRETS.lock() {
        *s = Some(Arc::new(set));
    }
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
    add_to(&SERVERS, addresses);
}

/// Чтение, дополнение и запись — под одной блокировкой: иначе две задачи, которые
/// добавляют адреса одновременно, затёрли бы друг друга, и адрес сервера ушёл бы в
/// журнал открытым.
fn add_to<I, S>(slot: &Mutex<Option<Arc<Servers>>>, addresses: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let new: Vec<String> = addresses
        .into_iter()
        .map(|a| normalize(a.as_ref()))
        .filter(|a| a.len() >= 4)
        .collect();
    if new.is_empty() {
        return;
    }
    if let Ok(mut s) = slot.lock() {
        let mut set: Servers = s.as_deref().cloned().unwrap_or_default();
        set.extend(new);
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
    let secrets = SECRETS
        .lock()
        .ok()
        .and_then(|s| s.clone())
        .unwrap_or_default();
    redact(s, &current(), &secrets)
}

/// Без списка секретов: в JSON-конфигах их скрывает имя поля (`SECRET_KEYS`).
fn text_with(s: &str, servers: &Servers) -> String {
    redact(s, servers, &Secrets::new())
}

fn redact(s: &str, servers: &Servers, secrets: &Secrets) -> String {
    let s = hide_secrets(s, secrets);
    let s = links(&s);
    let s = hide_servers(&s, servers);
    let s = uuids(&s);
    tokens(&s)
}

/// Чем отделён секрет от остального текста: `password=…`, `"…"`, `user:pass@`.
fn is_secret_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '=' | ':'
                | ','
                | ';'
                | '"'
                | '\''
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '<'
                | '>'
                | '@'
                | '/'
                | '?'
                | '&'
                | '#'
                | '|'
                | '`'
        )
}

/// Секреты — целыми кусками между разделителями (как адреса серверов: часть
/// другого слова не задевается). Секрет с разделителем внутри — подстрокой.
fn hide_secrets(s: &str, secrets: &Secrets) -> String {
    if secrets.is_empty() {
        return s.to_owned();
    }
    let mut text = s.to_owned();
    for secret in secrets.iter().filter(|x| x.contains(is_secret_delim)) {
        text = text.replace(secret.as_str(), HIDDEN);
    }
    let mut out = String::with_capacity(text.len());
    let mut start: Option<usize> = None;
    let flush = |out: &mut String, word: &str| {
        out.push_str(if secrets.contains(word) { HIDDEN } else { word });
    };
    for (i, c) in text.char_indices() {
        match (is_secret_delim(c), start) {
            (false, None) => start = Some(i),
            (true, Some(st)) => {
                flush(&mut out, &text[st..i]);
                start = None;
                out.push(c);
            }
            (true, None) => out.push(c),
            (false, Some(_)) => {}
        }
    }
    if let Some(st) = start {
        flush(&mut out, &text[st..]);
    }
    out
}

/// Двоеточие — часть слова, чтобы IPv6 не резался на куски; `адрес:порт` и
/// `tcp:адрес:порт` разбирает `hide_servers`.
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':')
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
    let is_server = |w: &str| w.len() >= 4 && servers.contains(&normalize(w));
    let flush = |out: &mut String, word: &str| {
        // Точка или двоеточие в конце слова — конец предложения, а не часть имени.
        let core = word.trim_end_matches(['.', ':']);
        if is_server(core) {
            out.push_str(SERVER);
        } else if core.contains(':') {
            // `адрес:порт`, `tcp:адрес:порт` — по частям.
            let parts: Vec<&str> = core
                .split(':')
                .map(|part| {
                    let p = part.trim_end_matches('.');
                    if is_server(p) {
                        SERVER
                    } else {
                        part
                    }
                })
                .collect();
            out.push_str(&parts.join(":"));
        } else {
            out.push_str(core);
        }
        out.push_str(&word[core.len()..]);
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

    /// IPv6-адрес сервера скрывается в любой записи: целиком, в скобках с портом и
    /// в полной форме; соседние адреса не задеваются.
    #[test]
    fn ipv6_servers_are_hidden() {
        let s: Servers = ["2001:db8::1", "vpn.example.com"]
            .into_iter()
            .map(normalize)
            .collect();
        assert_eq!(
            text_with("dial tcp [2001:db8::1]:443: timeout", &s),
            "dial tcp [[сервер]]:443: timeout"
        );
        assert_eq!(
            text_with("to 2001:DB8:0:0:0:0:0:1 failed", &s),
            "to [сервер] failed"
        );
        assert_eq!(text_with("to 2001:db8::12 ok", &s), "to 2001:db8::12 ok");
        assert_eq!(
            text_with("tcp:vpn.example.com:443 accepted", &s),
            "tcp:[сервер]:443 accepted"
        );
        assert_eq!(
            text_with("2026/11/07 16:43:49.135330 started", &s),
            "2026/11/07 16:43:49.135330 started"
        );
    }

    /// Короткие пароли не похожи на токен — их скрывает список секретов сервера.
    #[test]
    fn server_secrets_are_hidden() {
        let secrets: Secrets = ["hunter22", "p@ss:wd!"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let none = Servers::new();
        assert_eq!(
            redact("auth failed: password=hunter22 user", &none, &secrets),
            "auth failed: password=*** user"
        );
        assert_eq!(redact("got \"p@ss:wd!\"", &none, &secrets), "got \"***\"");
        // Часть другого слова не задевается; слишком короткий секрет не регистрируется.
        assert_eq!(redact("hunter222 abc", &none, &secrets), "hunter222 abc");
        set_secrets(["abc", "hunter22"]);
        assert_eq!(text("x hunter22 abc"), "x *** abc");
        set_secrets(Vec::<String>::new());
    }

    #[test]
    fn short_names_are_not_registered() {
        set_servers(["a", "vpn.example.com"]);
        assert_eq!(text("a b vpn.example.com"), "a b [сервер]");
        set_servers(Vec::<String>::new());
    }

    /// Адреса, которые добавляют одновременно (сервер и сервер загрузки XHTTP),
    /// не теряются.
    #[test]
    fn concurrent_additions_are_all_kept() {
        static SLOT: Mutex<Option<Arc<Servers>>> = Mutex::new(None);
        let threads: Vec<_> = (0..8)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 0..50 {
                        add_to(&SLOT, [format!("10.{t}.0.{i}")]);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let set = SLOT.lock().unwrap().clone().unwrap();
        assert_eq!(set.len(), 8 * 50);
    }
}
