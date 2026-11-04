//! Перенос подписок и ключей из других клиентов: v2rayN, Throne, NekoRay, Hiddify.
//!
//! Данные чужих клиентов только читаются. Здесь — преобразование их записей
//! (строка базы v2rayN, профиль NekoRay, исходящий sing-box из Throne и Hiddify)
//! в обычные ссылки `vless://`, `trojan://`, `ss://`, `hysteria2://`. Каждая
//! ссылка затем проходит тот же разбор, что и ссылка из подписки ([`crate::parser`]),
//! так что перенос не добавляет новых путей для непроверенных данных.
//!
//! Серверы из подписок не переносятся по одному: переносится ссылка подписки, а
//! серверы KVT загрузит сам — так они будут обновляться.

use crate::parser::{parse_uri, Entry};
use crate::Secret;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Client {
    V2rayN,
    Throne,
    NekoRay,
    Hiddify,
    Happ,
}

impl Client {
    pub fn title(self) -> &'static str {
        match self {
            Client::V2rayN => "v2rayN",
            Client::Throne => "Throne",
            Client::NekoRay => "NekoRay",
            Client::Hiddify => "Hiddify",
            Client::Happ => "Happ",
        }
    }
}

/// Подписка другого клиента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub name: String,
    pub url: Secret,
}

/// Сервер, добавленный в другом клиенте вручную, уже в виде ссылки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    pub protocol: String,
    pub link: Secret,
}

/// Всё, что нашлось в одном клиенте. Ссылки — секреты и в интерфейс не уходят.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collected {
    pub client: Client,
    /// Где лежат данные (каталог), для показа пользователю.
    pub location: String,
    pub subscriptions: Vec<Subscription>,
    pub servers: Vec<Server>,
    /// Причины, по которым записи не перенесены (по одной на запись).
    pub skipped: Vec<&'static str>,
    /// Пояснение, если перенести ничего нельзя (например, данные зашифрованы).
    pub note: Option<String>,
}

impl Collected {
    pub fn new(client: Client, location: impl Into<String>) -> Self {
        Self {
            client,
            location: location.into(),
            subscriptions: Vec::new(),
            servers: Vec::new(),
            skipped: Vec::new(),
            note: None,
        }
    }

    /// Подписка по ссылке; `http://` и мусор пропускаются, повторы — тоже.
    pub fn add_subscription(&mut self, name: &str, url: &str) {
        match subscription_url(url) {
            Ok(url) => {
                if !self.subscriptions.iter().any(|s| s.url.expose() == url) {
                    self.subscriptions.push(Subscription {
                        name: clean_name(name),
                        url: Secret::new(url),
                    });
                }
            }
            Err(reason) => self.skipped.push(reason),
        }
    }

    /// Сервер из уже собранной ссылки (или причина, почему её не собрать).
    pub fn add_server(&mut self, name: &str, link: Result<String, &'static str>) {
        match link.and_then(|l| check_link(&l).map(|protocol| (l, protocol))) {
            Ok((link, protocol)) => {
                if !self.servers.iter().any(|s| s.link.expose() == link) {
                    self.servers.push(Server {
                        name: clean_name(name),
                        protocol,
                        link: Secret::new(link),
                    });
                }
            }
            Err(reason) => self.skipped.push(reason),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty() && self.servers.is_empty()
    }

    /// Что показать пользователю перед переносом: без ссылок и ключей.
    pub fn preview(&self) -> Preview {
        let mut skipped: Vec<(&'static str, usize)> = Vec::new();
        for r in &self.skipped {
            match skipped.iter_mut().find(|(s, _)| s == r) {
                Some((_, n)) => *n += 1,
                None => skipped.push((r, 1)),
            }
        }
        Preview {
            client: self.client,
            title: self.client.title(),
            location: self.location.clone(),
            subscriptions: self
                .subscriptions
                .iter()
                .map(|s| PreviewSubscription {
                    name: s.name.clone(),
                    host: crate::netlog::host_of(s.url.expose()),
                })
                .collect(),
            servers: self
                .servers
                .iter()
                .map(|s| PreviewServer {
                    name: s.name.clone(),
                    protocol: s.protocol.clone(),
                })
                .collect(),
            skipped: skipped
                .into_iter()
                .map(|(reason, count)| Skipped { reason, count })
                .collect(),
            note: self.note.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub client: Client,
    pub title: &'static str,
    pub location: String,
    pub subscriptions: Vec<PreviewSubscription>,
    pub servers: Vec<PreviewServer>,
    pub skipped: Vec<Skipped>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewSubscription {
    pub name: String,
    /// Только адрес сервера подписки: в пути ссылки — токен.
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewServer {
    pub name: String,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub reason: &'static str,
    pub count: usize,
}

const MAX_NAME: usize = 120;

fn clean_name(name: &str) -> String {
    let n: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect();
    let n = n.trim();
    if n.is_empty() {
        "Без названия".into()
    } else {
        n.to_owned()
    }
}

fn subscription_url(raw: &str) -> Result<String, &'static str> {
    let raw = raw.trim();
    let url = url::Url::parse(raw).map_err(|_| "повреждённая ссылка подписки")?;
    match url.scheme() {
        "https" if url.host_str().is_some() => Ok(raw.to_owned()),
        "http" => Err("подписка по незащищённому http"),
        _ => Err("повреждённая ссылка подписки"),
    }
}

/// Ссылка разбирается тем же парсером, что и подписки. Возвращает протокол.
fn check_link(link: &str) -> Result<String, &'static str> {
    match parse_uri(link) {
        Ok(Entry::Server(_)) => Ok(protocol_title(link)),
        Ok(Entry::Info(_)) => Err("служебная запись провайдера"),
        Err(crate::parser::ParseError::Unsupported(_)) => {
            Err("протокол или настройка не поддерживается")
        }
        Err(_) => Err("неполные или повреждённые данные сервера"),
    }
}

fn protocol_title(link: &str) -> String {
    match link.split_once("://").map(|(s, _)| s) {
        Some("vless") => "VLESS",
        Some("trojan") => "Trojan",
        Some("ss") => "Shadowsocks",
        Some("hysteria2" | "hy2") => "Hysteria2",
        _ => "?",
    }
    .into()
}

// ── Сборка ссылок ──

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

fn enc(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

struct Link {
    scheme: &'static str,
    user: String,
    host: String,
    port: u64,
    name: String,
    params: Vec<(&'static str, String)>,
}

impl Link {
    fn param(&mut self, key: &'static str, value: Option<String>) {
        if let Some(v) = value.filter(|v| !v.trim().is_empty()) {
            self.params.push((key, v.trim().to_owned()));
        }
    }

    fn build(&self) -> Result<String, &'static str> {
        if self.host.trim().is_empty() || self.port == 0 || self.port > 65535 {
            return Err("неполные или повреждённые данные сервера");
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

fn text(m: &Map<String, Value>, key: &str) -> Option<String> {
    match m.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn number(m: &Map<String, Value>, key: &str) -> u64 {
    match m.get(key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn truthy(m: &Map<String, Value>, key: &str) -> bool {
    match m.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_u64() == Some(1),
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true"),
        _ => false,
    }
}

/// Вложенный JSON, сохранённый строкой (поля `ProtoExtra`/`TransportExtra` в v2rayN).
fn json_field(m: &Map<String, Value>, key: &str) -> Map<String, Value> {
    match m.get(key) {
        Some(Value::String(s)) => serde_json::from_str::<Value>(s)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default(),
        Some(Value::Object(o)) => o.clone(),
        _ => Map::new(),
    }
}

fn object<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    m.get(key).and_then(Value::as_object)
}

fn ss_user(method: &str, password: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"))
}

// ── v2rayN ──

/// Строка таблицы `ProfileItem` из `guiConfigs\guiNDB.db` (столбец → значение).
/// Поддерживаются и старые схемы (поля в столбцах), и новые (`ProtoExtra`,
/// `TransportExtra` с JSON) — новое значение берётся первым.
pub fn v2rayn_profile(m: &Map<String, Value>) -> Result<String, &'static str> {
    let pe = json_field(m, "ProtoExtra");
    let te = json_field(m, "TransportExtra");
    let pick =
        |extra: &Map<String, Value>, ek: &str, col: &str| text(extra, ek).or_else(|| text(m, col));
    let name = text(m, "Remarks").unwrap_or_default();
    let id = text(m, "Id").unwrap_or_default();
    let mut link = Link {
        scheme: "",
        user: enc(&id),
        host: text(m, "Address").unwrap_or_default(),
        port: number(m, "Port"),
        name,
        params: Vec::new(),
    };
    let stream = |link: &mut Link| {
        let network = text(m, "Network")
            .unwrap_or_else(|| "tcp".into())
            .to_ascii_lowercase();
        let network = if network == "raw" {
            "tcp".to_owned()
        } else {
            network
        };
        link.param("type", Some(network.clone()));
        match network.as_str() {
            "grpc" => link.param(
                "serviceName",
                text(&te, "GrpcServiceName").or_else(|| text(m, "Path")),
            ),
            "tcp" => link.param("headerType", pick(&te, "RawHeaderType", "HeaderType")),
            _ => {
                link.param("path", pick(&te, "Path", "Path"));
                link.param("host", pick(&te, "Host", "RequestHost"));
                if network == "xhttp" || network == "splithttp" {
                    link.param(
                        "mode",
                        text(&te, "XhttpMode").or_else(|| text(m, "HeaderType")),
                    );
                }
            }
        }
        link.param("security", text(m, "StreamSecurity"));
        link.param("sni", text(m, "Sni"));
        link.param("fp", text(m, "Fingerprint"));
        link.param("alpn", text(m, "Alpn"));
        link.param("pbk", text(m, "PublicKey"));
        link.param("sid", text(m, "ShortId"));
        link.param("spx", text(m, "SpiderX"));
        if truthy(m, "AllowInsecure") {
            link.param("allowInsecure", Some("1".into()));
        }
    };
    match number(m, "ConfigType") {
        5 => {
            link.scheme = "vless";
            link.param(
                "encryption",
                Some(pick(&pe, "VlessEncryption", "Security").unwrap_or_else(|| "none".into())),
            );
            link.param("flow", pick(&pe, "Flow", "Flow"));
            stream(&mut link);
        }
        6 => {
            link.scheme = "trojan";
            link.param("flow", pick(&pe, "Flow", "Flow"));
            stream(&mut link);
        }
        3 => {
            let method = pick(&pe, "SsMethod", "Security").unwrap_or_default();
            link.scheme = "ss";
            link.user = ss_user(&method, &id);
        }
        7 => {
            link.scheme = "hysteria2";
            link.param("sni", text(m, "Sni"));
            if truthy(m, "AllowInsecure") {
                link.param("insecure", Some("1".into()));
            }
            if let Some(pass) = text(&pe, "SalamanderPass").or_else(|| text(m, "Path")) {
                link.param("obfs", Some("salamander".into()));
                link.param("obfs-password", Some(pass));
            }
        }
        1 => return Err("VMess не поддерживается"),
        _ => return Err("протокол или настройка не поддерживается"),
    }
    link.build()
}

// ── NekoRay и старый Throne (config\profiles\*.json) ──

/// Профиль NekoRay: `{"type": "vless", "bean": {...}}`.
pub fn nekoray_profile(v: &Value) -> Result<(String, String), &'static str> {
    let kind = v.get("type").and_then(Value::as_str).unwrap_or_default();
    let bean = v
        .get("bean")
        .and_then(Value::as_object)
        .ok_or("неполные или повреждённые данные сервера")?;
    let name = text(bean, "name").unwrap_or_default();
    let mut link = Link {
        scheme: "",
        user: String::new(),
        host: text(bean, "addr").unwrap_or_default(),
        port: number(bean, "port"),
        name: name.clone(),
        params: Vec::new(),
    };
    let empty = Map::new();
    let stream = object(bean, "stream").unwrap_or(&empty);
    let apply_stream = |link: &mut Link| {
        let network = text(stream, "net").unwrap_or_else(|| "tcp".into());
        link.param("type", Some(network.clone()));
        match network.as_str() {
            "grpc" => link.param("serviceName", text(stream, "path")),
            "tcp" => link.param("headerType", text(stream, "h_type")),
            _ => {
                link.param("path", text(stream, "path"));
                link.param("host", text(stream, "host"));
            }
        }
        let security = text(stream, "sec");
        let reality = text(stream, "pbk").is_some();
        link.param(
            "security",
            if reality {
                Some("reality".into())
            } else {
                security
            },
        );
        link.param("sni", text(stream, "sni"));
        link.param("alpn", text(stream, "alpn"));
        link.param("fp", text(stream, "utls"));
        link.param("pbk", text(stream, "pbk"));
        link.param("sid", text(stream, "sid"));
        link.param("spx", text(stream, "spx"));
        if truthy(stream, "insecure") {
            link.param("allowInsecure", Some("1".into()));
        }
    };
    match kind {
        "vless" => {
            link.scheme = "vless";
            link.user = enc(&text(bean, "pass").unwrap_or_default());
            link.param("encryption", Some("none".into()));
            link.param("flow", text(bean, "flow"));
            apply_stream(&mut link);
        }
        "trojan" => {
            link.scheme = "trojan";
            link.user = enc(&text(bean, "pass").unwrap_or_default());
            apply_stream(&mut link);
        }
        "shadowsocks" => {
            if text(bean, "plugin").is_some() {
                return Err("плагины Shadowsocks не поддерживаются");
            }
            link.scheme = "ss";
            link.user = ss_user(
                &text(bean, "method").unwrap_or_default(),
                &text(bean, "pass").unwrap_or_default(),
            );
        }
        "hysteria2" => {
            link.scheme = "hysteria2";
            link.user = enc(&text(bean, "password").unwrap_or_default());
            link.param("sni", text(bean, "sni"));
            if truthy(bean, "allowInsecure") {
                link.param("insecure", Some("1".into()));
            }
            if let Some(pass) = text(bean, "obfsPassword") {
                link.param("obfs", Some("salamander".into()));
                link.param("obfs-password", Some(pass));
            }
        }
        "vmess" => return Err("VMess не поддерживается"),
        _ => return Err("протокол или настройка не поддерживается"),
    }
    Ok((name, link.build()?))
}

// ── sing-box: Throne (таблица profiles) и локальные профили Hiddify ──

/// Типы исходящих sing-box, которые не являются серверами (их молча пропускаем).
pub fn is_service_outbound(v: &Value) -> bool {
    matches!(
        v.get("type").and_then(Value::as_str),
        Some("direct" | "block" | "dns" | "selector" | "urltest")
    )
}

/// Исходящее sing-box (`{"type": "vless", "server": ..., "tls": {...}}`).
pub fn singbox_outbound(v: &Value, name: &str) -> Result<String, &'static str> {
    let o = v
        .as_object()
        .ok_or("неполные или повреждённые данные сервера")?;
    let kind = text(o, "type").unwrap_or_default();
    let name = if name.trim().is_empty() {
        text(o, "tag").unwrap_or_default()
    } else {
        name.to_owned()
    };
    let mut link = Link {
        scheme: "",
        user: String::new(),
        host: text(o, "server").unwrap_or_default(),
        port: number(o, "server_port"),
        name,
        params: Vec::new(),
    };
    let empty = Map::new();
    let tls = object(o, "tls").filter(|t| truthy(t, "enabled"));
    let apply_tls = |link: &mut Link| {
        let Some(t) = tls else { return };
        let reality = object(t, "reality").filter(|r| truthy(r, "enabled"));
        link.param(
            "security",
            Some(if reality.is_some() { "reality" } else { "tls" }.into()),
        );
        link.param("sni", text(t, "server_name"));
        if let Some(alpn) = t.get("alpn").and_then(Value::as_array) {
            let list: Vec<&str> = alpn.iter().filter_map(Value::as_str).collect();
            link.param("alpn", Some(list.join(",")));
        }
        link.param(
            "fp",
            object(t, "utls")
                .filter(|u| truthy(u, "enabled"))
                .and_then(|u| text(u, "fingerprint")),
        );
        if let Some(r) = reality {
            link.param("pbk", text(r, "public_key"));
            link.param("sid", text(r, "short_id"));
        }
        if truthy(t, "insecure") {
            link.param("allowInsecure", Some("1".into()));
        }
    };
    let apply_transport = |link: &mut Link| -> Result<(), &'static str> {
        let t = object(o, "transport").unwrap_or(&empty);
        let kind = text(t, "type").unwrap_or_else(|| "tcp".into());
        link.param("type", Some(kind.clone()));
        let host = object(t, "headers")
            .and_then(|h| text(h, "Host").or_else(|| text(h, "host")))
            .or_else(|| text(t, "host"));
        match kind.as_str() {
            "tcp" => {}
            "ws" | "httpupgrade" => {
                link.param("path", text(t, "path"));
                link.param("host", host);
            }
            "grpc" => link.param("serviceName", text(t, "service_name")),
            _ => return Err("протокол или настройка не поддерживается"),
        }
        Ok(())
    };
    match kind.as_str() {
        "vless" => {
            link.scheme = "vless";
            link.user = enc(&text(o, "uuid").unwrap_or_default());
            link.param("encryption", Some("none".into()));
            link.param("flow", text(o, "flow"));
            apply_transport(&mut link)?;
            apply_tls(&mut link);
        }
        "trojan" => {
            link.scheme = "trojan";
            link.user = enc(&text(o, "password").unwrap_or_default());
            apply_transport(&mut link)?;
            apply_tls(&mut link);
        }
        "shadowsocks" => {
            if text(o, "plugin").is_some() {
                return Err("плагины Shadowsocks не поддерживаются");
            }
            link.scheme = "ss";
            link.user = ss_user(
                &text(o, "method").unwrap_or_default(),
                &text(o, "password").unwrap_or_default(),
            );
        }
        "hysteria2" => {
            link.scheme = "hysteria2";
            link.user = enc(&text(o, "password").unwrap_or_default());
            if let Some(t) = tls {
                link.param("sni", text(t, "server_name"));
                if truthy(t, "insecure") {
                    link.param("insecure", Some("1".into()));
                }
            }
            if let Some(obfs) = object(o, "obfs") {
                link.param("obfs", text(obfs, "type"));
                link.param("obfs-password", text(obfs, "password"));
            }
        }
        "vmess" => return Err("VMess не поддерживается"),
        _ => return Err("протокол или настройка не поддерживается"),
    }
    link.build()
}

/// Серверы из полного конфига sing-box (локальный профиль Hiddify).
pub fn singbox_config(collected: &mut Collected, config: &Value) {
    let Some(outbounds) = config.get("outbounds").and_then(Value::as_array) else {
        return;
    };
    for o in outbounds.iter().filter(|o| !is_service_outbound(o)) {
        collected.add_server("", singbox_outbound(o, ""));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const PBK: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn server(link: &str) -> crate::Server {
        match parse_uri(link).unwrap() {
            Entry::Server(s) => *s,
            Entry::Info(_) => panic!("info"),
        }
    }

    #[test]
    fn v2rayn_new_schema_vless_reality() {
        let row = obj(json!({
            "ConfigType": 5, "Remarks": "NL #1", "Address": "nl.example.com", "Port": 443,
            "Id": UUID, "Network": "raw", "StreamSecurity": "reality", "Sni": "www.microsoft.com",
            "Fingerprint": "chrome", "PublicKey": PBK, "ShortId": "6ba8",
            "ProtoExtra": "{\"Flow\":\"xtls-rprx-vision\",\"VlessEncryption\":\"none\"}",
            "TransportExtra": "{}"
        }));
        let link = v2rayn_profile(&row).unwrap();
        let s = server(&link);
        assert_eq!(s.name, "NL #1");
        assert_eq!(s.address, "nl.example.com");
        assert_eq!(s.visible_sni(), Some("www.microsoft.com"));
        assert!(link.contains("flow=xtls-rprx-vision"));
    }

    #[test]
    fn v2rayn_old_schema_ws_tls_and_trojan() {
        let row = obj(json!({
            "ConfigType": 5, "Remarks": "WS", "Address": "ws.example.com", "Port": "8443",
            "Id": UUID, "Security": "none", "Network": "ws", "RequestHost": "cdn.example.com",
            "Path": "/ray?ed=2048", "StreamSecurity": "tls", "Sni": "cdn.example.com", "AllowInsecure": "false"
        }));
        let s = server(&v2rayn_profile(&row).unwrap());
        assert!(format!("{:?}", s.transport).contains("/ray?ed=2048"));

        let trojan = obj(json!({
            "ConfigType": 6, "Remarks": "T", "Address": "t.example.com", "Port": 443,
            "Id": "p@ss:word", "Network": "tcp", "StreamSecurity": "tls"
        }));
        assert!(server(&v2rayn_profile(&trojan).unwrap()).name == "T");
    }

    #[test]
    fn v2rayn_shadowsocks_and_hysteria2() {
        let ss = obj(json!({
            "ConfigType": 3, "Remarks": "SS", "Address": "1.2.3.4", "Port": 8388,
            "Id": "secret", "Security": "chacha20-ietf-poly1305"
        }));
        assert_eq!(server(&v2rayn_profile(&ss).unwrap()).address, "1.2.3.4");

        let hy = obj(json!({
            "ConfigType": 7, "Remarks": "HY", "Address": "hy.example.com", "Port": 443,
            "Id": "pw", "Sni": "hy.example.com", "Path": "obfs-secret"
        }));
        let link = v2rayn_profile(&hy).unwrap();
        assert!(link.contains("obfs=salamander") && link.contains("obfs-password=obfs-secret"));
        server(&link);
    }

    #[test]
    fn v2rayn_vmess_and_unknown_are_skipped_with_reason() {
        assert_eq!(
            v2rayn_profile(&obj(json!({"ConfigType": 1, "Address": "a", "Port": 1}))),
            Err("VMess не поддерживается")
        );
        assert!(v2rayn_profile(&obj(json!({"ConfigType": 9}))).is_err());
        assert!(v2rayn_profile(&obj(
            json!({"ConfigType": 5, "Address": "", "Port": 443, "Id": UUID})
        ))
        .is_err());
    }

    #[test]
    fn nekoray_profiles() {
        let v = json!({"type": "vless", "id": 3, "gid": 0, "bean": {
            "name": "Neko", "addr": "2001:db8::1", "port": 443, "pass": UUID, "flow": "xtls-rprx-vision",
            "stream": {"net": "tcp", "sec": "tls", "sni": "www.microsoft.com", "utls": "firefox",
                       "pbk": PBK, "sid": "6ba8"}
        }});
        let (name, link) = nekoray_profile(&v).unwrap();
        assert_eq!(name, "Neko");
        assert!(link.contains("@[2001:db8::1]:443"));
        assert!(link.contains("security=reality"));
        server(&link);

        let ss = json!({"type": "shadowsocks", "bean": {"name": "S", "addr": "s.example.com", "port": 8388,
            "method": "aes-256-gcm", "pass": "pw"}});
        server(&nekoray_profile(&ss).unwrap().1);
        let plugin = json!({"type": "shadowsocks", "bean": {"addr": "s", "port": 1, "plugin": "obfs-local"}});
        assert!(nekoray_profile(&plugin).is_err());
    }

    #[test]
    fn singbox_outbounds() {
        let v = json!({"type": "vless", "tag": "proxy", "server": "sb.example.com", "server_port": 443,
            "uuid": UUID, "flow": "xtls-rprx-vision",
            "tls": {"enabled": true, "server_name": "www.microsoft.com",
                    "utls": {"enabled": true, "fingerprint": "chrome"},
                    "reality": {"enabled": true, "public_key": PBK, "short_id": "6ba8"}}});
        let s = server(&singbox_outbound(&v, "Throne NL").unwrap());
        assert_eq!(s.name, "Throne NL");

        let ws = json!({"type": "trojan", "server": "t.example.com", "server_port": 443, "password": "pw",
            "tls": {"enabled": true, "server_name": "t.example.com"},
            "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "t.example.com"}}});
        let s = server(&singbox_outbound(&ws, "").unwrap());
        assert_eq!(s.address, "t.example.com");

        let hy = json!({"type": "hysteria2", "server": "h.example.com", "server_port": 443, "password": "pw",
            "tls": {"enabled": true, "server_name": "h.example.com"},
            "obfs": {"type": "salamander", "password": "x"}});
        server(&singbox_outbound(&hy, "H").unwrap());

        assert!(singbox_outbound(&json!({"type": "tuic"}), "").is_err());
        assert!(is_service_outbound(&json!({"type": "direct"})));
    }

    #[test]
    fn collected_dedups_and_hides_secrets_in_preview() {
        let mut c = Collected::new(Client::V2rayN, r"C:\v2rayN");
        c.add_subscription("Мой VPN", "https://sub.example.com/api/SECRET-TOKEN");
        c.add_subscription("Дубль", "https://sub.example.com/api/SECRET-TOKEN");
        c.add_subscription("Старая", "http://old.example.com/sub");
        c.add_subscription("Мусор", "not a url");
        let row = obj(json!({"ConfigType": 1}));
        c.add_server("vmess", v2rayn_profile(&row));
        c.add_server("vmess2", v2rayn_profile(&row));
        let v = json!({"type": "trojan", "server": "t.example.com", "server_port": 443, "password": "SECRET-PASS"});
        c.add_server("T", singbox_outbound(&v, "T"));
        c.add_server("T", singbox_outbound(&v, "T"));

        assert_eq!(c.subscriptions.len(), 1);
        assert_eq!(c.servers.len(), 1);
        let p = c.preview();
        let shown = serde_json::to_string(&p).unwrap();
        assert!(!shown.contains("SECRET"), "{shown}");
        assert_eq!(p.subscriptions[0].host, "sub.example.com");
        assert_eq!(p.servers[0].protocol, "Trojan");
        assert!(shown.contains("\"client\":\"v2rayn\""));
        assert!(p
            .skipped
            .iter()
            .any(|s| s.reason == "VMess не поддерживается" && s.count == 2));
        assert!(p
            .skipped
            .iter()
            .any(|s| s.reason == "подписка по незащищённому http"));
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_name("  \u{7}\n "), "Без названия");
        assert_eq!(clean_name(&"x".repeat(500)).len(), MAX_NAME);
    }
}
