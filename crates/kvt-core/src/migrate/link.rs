//! Сборка ссылки `vless://`, `trojan://`, `ss://`, `hysteria2://` из полей чужого профиля и
//! чтение полей JSON, которые для этого нужны. Разбор самой ссылки — в `crate::parser`.

use crate::i18n::tr;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::{Map, Value};

/// Символы, которые экранируются в имени пользователя, параметрах и названии.
const COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub(super) fn enc(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

pub(super) struct Link {
    pub(super) scheme: &'static str,
    pub(super) user: String,
    pub(super) host: String,
    pub(super) port: u64,
    pub(super) name: String,
    pub(super) params: Vec<(&'static str, String)>,
}

impl Link {
    pub(super) fn param(&mut self, key: &'static str, value: Option<String>) {
        if let Some(v) = value.filter(|v| !v.trim().is_empty()) {
            self.params.push((key, v.trim().to_owned()));
        }
    }

    pub(super) fn build(&self) -> Result<String, &'static str> {
        if self.host.trim().is_empty() || self.port == 0 || self.port > 65535 {
            return Err(tr(
                "неполные или повреждённые данные сервера",
                "incomplete or broken server data",
            ));
        }
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let query: Vec<String> = self
            .params
            .iter()
            .map(|(k, v)| format!("{k}={}", enc(v)))
            .collect();
        let query = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        Ok(format!(
            "{}://{}@{}:{}{}#{}",
            self.scheme,
            self.user,
            host,
            self.port,
            query,
            enc(&self.name)
        ))
    }
}

pub(super) fn text(m: &Map<String, Value>, key: &str) -> Option<String> {
    match m.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub(super) fn number(m: &Map<String, Value>, key: &str) -> u64 {
    match m.get(key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

pub(super) fn truthy(m: &Map<String, Value>, key: &str) -> bool {
    match m.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_u64() == Some(1),
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true"),
        _ => false,
    }
}

/// Вложенный JSON, сохранённый строкой (поля `ProtoExtra`/`TransportExtra` в v2rayN).
pub(super) fn json_field(m: &Map<String, Value>, key: &str) -> Map<String, Value> {
    match m.get(key) {
        Some(Value::String(s)) => serde_json::from_str::<Value>(s)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default(),
        Some(Value::Object(o)) => o.clone(),
        _ => Map::new(),
    }
}

pub(super) fn object<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    m.get(key).and_then(Value::as_object)
}

pub(super) fn ss_user(method: &str, password: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"))
}
