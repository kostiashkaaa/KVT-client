//! `extra` у XHTTP: xmux, паддинг, заголовки, раздельная загрузка (`downloadSettings`).
//! Провайдеры кладут это в ссылку (`extra=` с JSON) и в JSON-конфиги Xray — без этих
//! настроек часть серверов в России не работает.
//!
//! Данные недоверенные, а конфиг запускает служба от SYSTEM, поэтому — белый список
//! полей с проверкой типов. `downloadSettings` в Xray — полный `streamSettings`: там
//! бывают пути к файлам (`certificates`, `masterKeyLog`) и `sockopt`. Из него берутся
//! только адрес, порт, XHTTP и TLS/REALITY с безопасными полями. Неизвестное
//! отбрасывается: Xray подставит значение по умолчанию.

use super::ParseError;
use serde_json::{Map, Value};

/// Длиннее не принимаем — ссылка и так ограничена `MAX_URI_LEN`.
const MAX_EXTRA_BYTES: usize = 6 * 1024;
const MAX_STRING: usize = 256;
const MAX_HEADERS: usize = 16;

#[derive(Clone, Copy)]
enum Kind {
    Bool,
    Int,
    /// `число` или строка `от-до`.
    Range,
    Text,
}

/// Поля `SplitHTTPConfig` Xray 26 (кроме host/path/mode — они в ссылке отдельно).
const FIELDS: &[(&str, Kind)] = &[
    ("xPaddingBytes", Kind::Range),
    ("xPaddingObfsMode", Kind::Bool),
    ("xPaddingKey", Kind::Text),
    ("xPaddingHeader", Kind::Text),
    ("xPaddingPlacement", Kind::Text),
    ("xPaddingMethod", Kind::Text),
    ("uplinkHTTPMethod", Kind::Text),
    ("sessionIDPlacement", Kind::Text),
    ("sessionIDKey", Kind::Text),
    ("sessionIDTable", Kind::Text),
    ("sessionIDLength", Kind::Range),
    ("seqPlacement", Kind::Text),
    ("seqKey", Kind::Text),
    ("uplinkDataPlacement", Kind::Text),
    ("uplinkDataKey", Kind::Text),
    ("uplinkChunkSize", Kind::Range),
    ("noGRPCHeader", Kind::Bool),
    ("noSSEHeader", Kind::Bool),
    ("scMaxEachPostBytes", Kind::Range),
    ("scMinPostsIntervalMs", Kind::Range),
    ("scMaxBufferedPosts", Kind::Int),
    ("scStreamUpServerSecs", Kind::Range),
];

const XMUX_FIELDS: &[(&str, Kind)] = &[
    ("maxConcurrency", Kind::Range),
    ("maxConnections", Kind::Range),
    ("cMaxReuseTimes", Kind::Range),
    ("hMaxRequestTimes", Kind::Range),
    ("hMaxReusableSecs", Kind::Range),
    ("hKeepAlivePeriod", Kind::Int),
];

const TLS_FIELDS: &[(&str, Kind)] = &[
    ("serverName", Kind::Text),
    ("fingerprint", Kind::Text),
    ("allowInsecure", Kind::Bool),
    ("echConfigList", Kind::Text),
];

const REALITY_FIELDS: &[(&str, Kind)] = &[
    ("serverName", Kind::Text),
    ("fingerprint", Kind::Text),
    ("publicKey", Kind::Text),
    ("shortId", Kind::Text),
    ("spiderX", Kind::Text),
];

fn bad(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "extra",
        reason,
    }
}

fn unsupported() -> ParseError {
    ParseError::Unsupported(crate::i18n::tr(
        "XHTTP с загрузкой не через XHTTP",
        "XHTTP with download not over XHTTP",
    ))
}

/// Значение подходящего типа или `None` (поле отбрасывается).
fn checked(v: &Value, kind: Kind) -> Option<Value> {
    let ok = match kind {
        Kind::Bool => v.is_boolean(),
        Kind::Int => v
            .as_i64()
            .is_some_and(|n| (0..=i64::from(i32::MAX)).contains(&n)),
        Kind::Range => match v {
            Value::Number(n) => n
                .as_i64()
                .is_some_and(|n| (0..=i64::from(i32::MAX)).contains(&n)),
            Value::String(s) => is_range(s),
            _ => false,
        },
        Kind::Text => v
            .as_str()
            .is_some_and(|s| s.len() <= MAX_STRING && !s.chars().any(char::is_control)),
    };
    ok.then(|| v.clone())
}

/// `100` или `100-200`.
pub(crate) fn is_range(s: &str) -> bool {
    let num = |p: &str| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit());
    match s.split_once('-') {
        Some((a, b)) => num(a) && num(b),
        None => num(s),
    }
}

fn copy_fields(src: &Value, fields: &[(&str, Kind)], out: &mut Map<String, Value>) {
    for (key, kind) in fields {
        if let Some(v) = src.get(*key).and_then(|v| checked(v, *kind)) {
            out.insert((*key).to_owned(), v);
        }
    }
}

/// Имя заголовка — токен HTTP; значение — строка без управляющих символов.
fn headers(src: &Value) -> Option<Value> {
    let map = src.as_object()?;
    let token = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    let out: Map<String, Value> = map
        .iter()
        .filter(|(k, _)| token(k))
        .filter_map(|(k, v)| Some((k.clone(), checked(v, Kind::Text)?)))
        .take(MAX_HEADERS)
        .collect();
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Настройки XHTTP из белого списка (без `downloadSettings`).
fn xhttp_fields(src: &Value, out: &mut Map<String, Value>) {
    copy_fields(src, FIELDS, out);
    if let Some(h) = src.get("headers").and_then(headers) {
        out.insert("headers".into(), h);
    }
    if let Some(xmux) = src.get("xmux") {
        let mut m = Map::new();
        copy_fields(xmux, XMUX_FIELDS, &mut m);
        if !m.is_empty() {
            out.insert("xmux".into(), Value::Object(m));
        }
    }
}

/// `downloadSettings`: только XHTTP по TLS, REALITY или без шифрования.
fn download(src: &Value) -> Result<Value, ParseError> {
    let mut out = Map::new();
    let address = src
        .get("address")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty() && a.len() <= 253)
        .filter(|a| {
            a.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:_[]".contains(&b))
        })
        .ok_or(bad(crate::i18n::tr(
            "у downloadSettings нет адреса",
            "downloadSettings has no address",
        )))?;
    out.insert("address".into(), address.into());
    let port = src
        .get("port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .ok_or(bad(crate::i18n::tr(
            "у downloadSettings нет порта",
            "downloadSettings has no port",
        )))?;
    out.insert("port".into(), port.into());

    let network = src
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("xhttp");
    if !matches!(network, "xhttp" | "splithttp") {
        return Err(unsupported());
    }
    out.insert("network".into(), "xhttp".into());
    let settings = src
        .get("xhttpSettings")
        .or_else(|| src.get("splithttpSettings"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut x = Map::new();
    for key in ["host", "path", "mode"] {
        if let Some(v) = settings.get(key).and_then(|v| checked(v, Kind::Text)) {
            x.insert(key.into(), v);
        }
    }
    // Вложенный `extra` в Xray заменяет поля рядом с ним — так же и здесь.
    let inner = settings
        .get("extra")
        .filter(|e| e.is_object())
        .unwrap_or(&settings);
    xhttp_fields(inner, &mut x);
    out.insert("xhttpSettings".into(), Value::Object(x));

    let security = src
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let (key, fields) = match security {
        "none" | "" => ("", &[][..]),
        "tls" => ("tlsSettings", TLS_FIELDS),
        "reality" => ("realitySettings", REALITY_FIELDS),
        _ => return Err(unsupported()),
    };
    if !key.is_empty() {
        out.insert("security".into(), security.into());
        let mut s = Map::new();
        let from = src.get(key).cloned().unwrap_or(Value::Null);
        copy_fields(&from, fields, &mut s);
        if let Some(alpn) = from.get("alpn").and_then(Value::as_array) {
            let list: Vec<Value> = alpn
                .iter()
                .filter_map(|a| checked(a, Kind::Text))
                .take(8)
                .collect();
            if !list.is_empty() {
                s.insert("alpn".into(), Value::Array(list));
            }
        }
        out.insert(key.into(), Value::Object(s));
    }
    Ok(Value::Object(out))
}

/// Объект настроек XHTTP провайдера → `extra` для конфига Xray (JSON-строка) или
/// `None`, если из белого списка ничего не осталось.
pub(crate) fn sanitize_value(v: &Value) -> Result<Option<String>, ParseError> {
    if !v.is_object() {
        return Err(bad(crate::i18n::tr(
            "ожидается объект JSON",
            "expected a JSON object",
        )));
    }
    let mut out = Map::new();
    xhttp_fields(v, &mut out);
    if let Some(d) = v.get("downloadSettings").filter(|d| !d.is_null()) {
        out.insert("downloadSettings".into(), download(d)?);
    }
    if out.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(&Value::Object(out))
        .map(Some)
        .map_err(|_| bad("JSON"))
}

/// Параметр `extra` ссылки.
pub(crate) fn sanitize(text: &str) -> Result<Option<String>, ParseError> {
    if text.len() > MAX_EXTRA_BYTES {
        return Err(ParseError::TooLong);
    }
    let v: Value =
        serde_json::from_str(text).map_err(|_| bad(crate::i18n::tr("не JSON", "not JSON")))?;
    sanitize_value(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn clean(v: Value) -> Value {
        serde_json::from_str(&sanitize(&v.to_string()).unwrap().unwrap()).unwrap()
    }

    #[test]
    fn known_fields_are_kept() {
        let out = clean(json!({
            "xPaddingBytes": "100-1000",
            "noGRPCHeader": true,
            "scMaxBufferedPosts": 30,
            "headers": { "User-Agent": "Mozilla/5.0", "bad header": "x" },
            "xmux": { "maxConcurrency": "16-32", "hKeepAlivePeriod": 0, "evil": 1 }
        }));
        assert_eq!(out["xPaddingBytes"], "100-1000");
        assert_eq!(out["noGRPCHeader"], true);
        assert_eq!(out["scMaxBufferedPosts"], 30);
        assert_eq!(out["headers"], json!({ "User-Agent": "Mozilla/5.0" }));
        assert_eq!(
            out["xmux"],
            json!({ "maxConcurrency": "16-32", "hKeepAlivePeriod": 0 })
        );
    }

    #[test]
    fn wrong_types_and_unknown_fields_are_dropped() {
        let out = clean(json!({
            "xPaddingBytes": "1-x",
            "noSSEHeader": "yes",
            "scMaxBufferedPosts": -5,
            "h2Params": { "a": 1 },
            "extra": { "xPaddingBytes": "1-2" },
            "uplinkHTTPMethod": "PUT"
        }));
        assert_eq!(out, json!({ "uplinkHTTPMethod": "PUT" }));
        assert_eq!(sanitize(r#"{"foo": 1}"#).unwrap(), None);
    }

    #[test]
    fn download_settings_lose_files_and_sockopt() {
        let out = clean(json!({
            "downloadSettings": {
                "address": "dl.example.com", "port": 443, "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "dl.example.com", "alpn": ["h2"], "fingerprint": "firefox",
                    "certificates": [{ "certificateFile": "C:\\Windows\\System32\\config\\SAM" }],
                    "masterKeyLog": "C:\\keys.log"
                },
                "xhttpSettings": { "path": "/d", "xPaddingBytes": "1-10", "downloadSettings": {} },
                "sockopt": { "interface": "Ethernet", "dialerProxy": "x" },
                "finalmask": { "tcp": [] }
            }
        }));
        let d = &out["downloadSettings"];
        assert_eq!(d["address"], "dl.example.com");
        assert_eq!(d["port"], 443);
        assert_eq!(
            d["tlsSettings"],
            json!({ "serverName": "dl.example.com", "fingerprint": "firefox", "alpn": ["h2"] })
        );
        assert_eq!(
            d["xhttpSettings"],
            json!({ "path": "/d", "xPaddingBytes": "1-10" })
        );
        assert!(d.get("sockopt").is_none() && d.get("finalmask").is_none());
    }

    #[test]
    fn bad_download_settings_are_errors() {
        for d in [
            json!({ "port": 443 }),
            json!({ "address": "a b", "port": 443 }),
            json!({ "address": "dl.example.com", "port": 70000 }),
            json!({ "address": "dl.example.com", "port": 443, "network": "ws" }),
            json!({ "address": "dl.example.com", "port": 443, "security": "xtls" }),
        ] {
            assert!(
                sanitize(&json!({ "downloadSettings": d }).to_string()).is_err(),
                "{d}"
            );
        }
    }

    #[test]
    fn junk_is_rejected() {
        assert!(sanitize("not json").is_err());
        assert!(sanitize("[1,2]").is_err());
        assert!(matches!(
            sanitize(&format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_EXTRA_BYTES))),
            Err(ParseError::TooLong)
        ));
        assert!(is_range("10") && is_range("10-20") && !is_range("-1") && !is_range("1-"));
    }
}
