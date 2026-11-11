//! Подписка в виде JSON-конфигов Xray. Так панели провайдеров (Remnawave, Marzban)
//! отвечают v2rayN 7, v2rayNG и Happ: массив полных конфигов, у каждого `remarks` и
//! список `outbounds`. KVT строит конфиг ядра сам, поэтому из каждого конфига берётся
//! одно подключение — помеченное `proxy`, иначе первое поддерживаемое — и переводится в
//! обычную ссылку, которую проверяют те же парсеры, что и ссылки из подписки.
//!
//! Переносятся и настройки, без которых сервер у провайдера может не работать:
//! фрагментация (`finalmask` или `sockopt.dialerProxy` во `freedom` с `fragment`),
//! mux и остальные поля XHTTP (`extra`) — дальше их проверяют парсеры ссылок.
//! Не переносятся: балансировщики провайдера (из нескольких подключений берётся одно)
//! и правила маршрутизации — маршруты у KVT свои.

use super::{parse_uri, Entry, ParseError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::Value;
use url::form_urlencoded::Serializer;

/// Больше конфигов не разбираем — та же защита, что и лимит строк.
const MAX_CONFIGS: usize = 10_000;

/// Что оставлять в userinfo и фрагменте как есть; остальное — `%XX`.
const KEEP: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const SUPPORTED: [&str; 5] = ["vless", "vmess", "trojan", "shadowsocks", "hysteria"];

/// `None` — это не конфиги Xray (не JSON или ни в одном нет `outbounds`).
/// Иначе по записи на каждый конфиг с `outbounds`, в порядке подписки.
pub(super) fn parse(text: &str) -> Option<Vec<Result<Entry, ParseError>>> {
    Some(
        links(text)?
            .into_iter()
            .map(|uri| parse_uri(&uri?))
            .collect(),
    )
}

/// Те же конфиги как ссылки `scheme://…#name` (по одной на конфиг).
pub(super) fn links(text: &str) -> Option<Vec<Result<String, ParseError>>> {
    let root: Value = serde_json::from_str(text).ok()?;
    let configs: Vec<&Value> = match &root {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![&root],
        _ => return None,
    };
    let configs: Vec<&Value> = configs
        .into_iter()
        .filter(|c| c.get("outbounds").is_some_and(Value::is_array))
        .take(MAX_CONFIGS)
        .collect();
    if configs.is_empty() {
        return None;
    }
    Some(configs.into_iter().map(config_uri).collect())
}

fn config_uri(config: &Value) -> Result<String, ParseError> {
    let outbounds = config["outbounds"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let supported = |o: &&Value| str_at(o, "protocol").is_some_and(|p| SUPPORTED.contains(&p));
    let outbound = outbounds
        .iter()
        .filter(supported)
        .find(|o| str_at(o, "tag") == Some("proxy"))
        .or_else(|| outbounds.iter().find(supported))
        .ok_or(ParseError::Unsupported(crate::i18n::tr(
            "в конфиге нет подключения VLESS, VMess, Trojan, Shadowsocks или Hysteria2",
            "the config has no VLESS, VMess, Trojan, Shadowsocks or Hysteria2 connection",
        )))?;
    let name = str_at(config, "remarks").unwrap_or_default();
    outbound_uri(outbound, name, outbounds)
}

/// Подключение из конфига Xray как ссылка `scheme://…#name`. `all` — все подключения
/// конфига: в одном из них может быть фрагментация (`dialerProxy`).
fn outbound_uri(o: &Value, name: &str, all: &[Value]) -> Result<String, ParseError> {
    let settings = &o["settings"];
    let stream = &o["streamSettings"];
    let mut q = Serializer::new(String::new());

    let (scheme, userinfo, server) = match str_at(o, "protocol") {
        Some("vless") => {
            let server = &settings["vnext"][0];
            let user = &server["users"][0];
            let id = required(user, "id")?;
            if let Some(flow) = str_at(user, "flow").filter(|f| !f.is_empty()) {
                q.append_pair("flow", flow);
            }
            if let Some(enc) = str_at(user, "encryption") {
                q.append_pair("encryption", enc);
            }
            ("vless", encode(id), server)
        }
        Some("vmess") => {
            let server = &settings["vnext"][0];
            let user = &server["users"][0];
            let id = required(user, "id")?;
            if user["alterId"].as_u64().is_some_and(|a| a > 0) {
                return Err(ParseError::Unsupported(crate::i18n::tr(
                    "VMess с alterId (устаревший вариант)",
                    "VMess with alterId (legacy)",
                )));
            }
            if let Some(cipher) = str_at(user, "security") {
                q.append_pair("encryption", cipher);
            }
            ("vmess", encode(id), server)
        }
        Some("trojan") => {
            let server = &settings["servers"][0];
            ("trojan", encode(required(server, "password")?), server)
        }
        Some("shadowsocks") => {
            let server = &settings["servers"][0];
            let method = required(server, "method")?;
            let password = required(server, "password")?;
            // У Shadowsocks транспорт и TLS в ссылке не задаются — только адрес и ключ.
            let userinfo = URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
            let (host, port) = host_port(server)?;
            return Ok(format!("ss://{userinfo}@{host}:{port}#{}", encode(name)));
        }
        Some("hysteria") => return hysteria_uri(o, name),
        _ => {
            return Err(ParseError::Unsupported(crate::i18n::tr(
                "тип подключения",
                "connection type",
            )))
        }
    };

    let (host, port) = host_port(server)?;
    stream_query(stream, &mut q);
    if let Some(fragment) = fragment_param(stream, all) {
        q.append_pair("fragment", &fragment);
    }
    if o["mux"]["enabled"].as_bool() == Some(true) {
        // Без `concurrency` Xray берёт 8; 0 и меньше — mux для TCP выключен.
        let n = o["mux"]["concurrency"].as_i64().unwrap_or(8);
        if (1..=1024).contains(&n) {
            q.append_pair("mux", &n.to_string());
        }
    }
    Ok(format!(
        "{scheme}://{userinfo}@{host}:{port}?{}#{}",
        q.finish(),
        encode(name)
    ))
}

/// Hysteria2 в Xray: адрес в `settings`, пароль в `streamSettings.hysteriaSettings.auth`.
fn hysteria_uri(o: &Value, name: &str) -> Result<String, ParseError> {
    let settings = &o["settings"];
    let stream = &o["streamSettings"];
    let version = settings["version"]
        .as_u64()
        .or_else(|| stream["hysteriaSettings"]["version"].as_u64());
    if version.is_some_and(|v| v != 2) {
        return Err(ParseError::Unsupported(crate::i18n::tr(
            "Hysteria первой версии",
            "Hysteria v1",
        )));
    }
    let auth = required(&stream["hysteriaSettings"], "auth")?;
    let (host, port) = host_port(settings)?;
    let mut q = Serializer::new(String::new());
    let tls = &stream["tlsSettings"];
    if let Some(sni) = str_at(tls, "serverName") {
        q.append_pair("sni", sni);
    }
    if tls["allowInsecure"].as_bool() == Some(true) {
        q.append_pair("insecure", "1");
    }
    if let Some(ech) = str_at(tls, "echConfigList").filter(|v| !v.is_empty()) {
        q.append_pair("ech", ech);
    }
    Ok(format!(
        "hysteria2://{}@{host}:{port}?{}#{}",
        encode(auth),
        q.finish(),
        encode(name)
    ))
}

/// `streamSettings` → параметры ссылки (`type`, `security`, `sni`, `pbk`, …).
fn stream_query(stream: &Value, q: &mut Serializer<'_, String>) {
    let network = str_at(stream, "network").unwrap_or("tcp");
    q.append_pair("type", network);
    let transport = match network {
        "tcp" | "raw" => {
            let settings = stream
                .get("tcpSettings")
                .or_else(|| stream.get("rawSettings"));
            if let Some(header) = settings.and_then(|s| str_at(&s["header"], "type")) {
                q.append_pair("headerType", header);
            }
            None
        }
        "ws" => stream.get("wsSettings"),
        "httpupgrade" => stream.get("httpupgradeSettings"),
        "xhttp" | "splithttp" => stream
            .get("xhttpSettings")
            .or_else(|| stream.get("splithttpSettings")),
        "grpc" => {
            if let Some(service) = str_at(&stream["grpcSettings"], "serviceName") {
                q.append_pair("serviceName", service);
            }
            None
        }
        _ => None,
    };
    if let Some(t) = transport {
        if let Some(path) = str_at(t, "path") {
            q.append_pair("path", path);
        }
        let host = str_at(t, "host").or_else(|| str_at(&t["headers"], "Host"));
        if let Some(host) = host.filter(|h| !h.is_empty()) {
            q.append_pair("host", host);
        }
        if let Some(mode) = str_at(t, "mode") {
            q.append_pair("mode", mode);
        }
        if matches!(network, "xhttp" | "splithttp") {
            // `extra` в Xray заменяет всё, кроме host/path/mode; без него те же поля
            // лежат прямо в xhttpSettings. Белый список — у парсера ссылки.
            let extra = match t.get("extra").filter(|e| e.is_object()) {
                Some(e) => e.clone(),
                None => {
                    let mut rest = t.clone();
                    if let Some(map) = rest.as_object_mut() {
                        for key in ["path", "host", "mode", "extra"] {
                            map.remove(key);
                        }
                    }
                    rest
                }
            };
            if extra.as_object().is_some_and(|m| !m.is_empty()) {
                q.append_pair("extra", &extra.to_string());
            }
        }
    }

    let security = str_at(stream, "security").unwrap_or("none");
    q.append_pair("security", security);
    let (settings, keys): (&Value, &[(&str, &str)]) = match security {
        "tls" => (
            &stream["tlsSettings"],
            &[
                ("serverName", "sni"),
                ("fingerprint", "fp"),
                ("echConfigList", "ech"),
            ],
        ),
        "reality" => (
            &stream["realitySettings"],
            &[
                ("serverName", "sni"),
                ("fingerprint", "fp"),
                ("publicKey", "pbk"),
                ("shortId", "sid"),
                ("spiderX", "spx"),
            ],
        ),
        _ => return,
    };
    for (from, to) in keys {
        if let Some(v) = str_at(settings, from).filter(|v| !v.is_empty()) {
            q.append_pair(to, v);
        }
    }
    if let Some(alpn) = settings["alpn"].as_array() {
        let list: Vec<&str> = alpn.iter().filter_map(Value::as_str).collect();
        if !list.is_empty() {
            q.append_pair("alpn", &list.join(","));
        }
    }
    if settings["allowInsecure"].as_bool() == Some(true) {
        q.append_pair("allowInsecure", "1");
    }
}

/// Фрагментация как параметр ссылки `пакеты,длина,пауза`: из `finalmask.tcp` или
/// из `freedom` с `fragment`, через который подключение идёт по `dialerProxy`.
fn fragment_param(stream: &Value, all: &[Value]) -> Option<String> {
    let range = |v: &Value| match v {
        Value::String(s) => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let make = |f: &Value, delay_key: &str| -> Option<String> {
        let packets = str_at(f, "packets")
            .filter(|p| !p.is_empty())
            .unwrap_or("tlshello");
        let length = range(&f["length"])?;
        let delay = range(&f[delay_key]).unwrap_or_else(|| "0".into());
        // Негодные значения — без фрагментации, как раньше, а не отказ от сервера.
        super::stream::fragment_from(packets, &length, &delay).ok()?;
        Some(format!("{packets},{length},{delay}"))
    };
    if let Some(mask) = stream["finalmask"]["tcp"]
        .as_array()
        .and_then(|m| m.iter().find(|m| str_at(m, "type") == Some("fragment")))
    {
        return make(&mask["settings"], "delay");
    }
    let via = str_at(&stream["sockopt"], "dialerProxy")?;
    let freedom = all
        .iter()
        .find(|o| str_at(o, "tag") == Some(via) && str_at(o, "protocol") == Some("freedom"))?;
    make(&freedom["settings"]["fragment"], "interval")
}

fn host_port(server: &Value) -> Result<(String, u16), ParseError> {
    let address = required(server, "address")?;
    let port = server["port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .ok_or(ParseError::MissingField(crate::i18n::tr("порт", "port")))?;
    // IPv6 в ссылке — в квадратных скобках.
    let host = if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]")
    } else {
        address.to_owned()
    };
    Ok((host, port))
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn required<'a>(v: &'a Value, key: &'static str) -> Result<&'a str, ParseError> {
    str_at(v, key)
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::MissingField(key))
}

pub(super) fn encode(s: &str) -> String {
    utf8_percent_encode(s, KEEP).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Fingerprint, Protocol, Security, Transport};

    const ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const PBK: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

    fn servers(text: &str) -> Vec<crate::model::Server> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|e| match e.unwrap() {
                Entry::Server(s) => *s,
                Entry::Info(i) => panic!("служебная запись {i}"),
            })
            .collect()
    }

    fn sample() -> String {
        serde_json::json!([
            {
                "remarks": "🇩🇪 Франкфурт ⚡",
                "outbounds": [
                    { "tag": "direct", "protocol": "freedom" },
                    {
                        "tag": "proxy", "protocol": "vless",
                        "settings": { "vnext": [{ "address": "de.example.com", "port": 8443,
                            "users": [{ "id": ID, "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
                        "streamSettings": { "network": "tcp", "tcpSettings": {}, "security": "reality",
                            "realitySettings": { "serverName": "www.example.org", "publicKey": PBK,
                                "shortId": "2356d1ae4b", "fingerprint": "qq" },
                            "finalmask": { "tcp": [{ "type": "fragment" }] } }
                    },
                    { "tag": "hy2", "protocol": "hysteria",
                      "settings": { "address": "hy.example.com", "port": 443, "version": 2 } }
                ]
            },
            {
                "remarks": "LTE №1",
                "outbounds": [{
                    "tag": "l1", "protocol": "vless",
                    "settings": { "vnext": [{ "address": "ws.example.com", "port": 443,
                        "users": [{ "id": ID, "encryption": "none", "flow": "" }] }] },
                    "streamSettings": { "network": "ws",
                        "wsSettings": { "path": "/a b?x=1", "headers": { "Host": "cdn.example.com" } },
                        "security": "tls",
                        "tlsSettings": { "serverName": "cdn.example.com", "fingerprint": "firefox", "alpn": ["http/1.1"] } },
                    "mux": { "enabled": true }
                }]
            },
            {
                "remarks": "Gaming",
                "outbounds": [{
                    "tag": "proxy", "protocol": "hysteria",
                    "settings": { "address": "hy.example.com", "port": 443, "version": 2 },
                    "streamSettings": { "network": "hysteria",
                        "hysteriaSettings": { "version": 2, "auth": "p@ss:word" },
                        "security": "tls", "tlsSettings": { "serverName": "hy.example.com", "alpn": ["h3"] } }
                }]
            },
            {
                "remarks": "gRPC",
                "outbounds": [{
                    "tag": "proxy", "protocol": "vless",
                    "settings": { "vnext": [{ "address": "2001:db8::1", "port": 443,
                        "users": [{ "id": ID, "encryption": "none" }] }] },
                    "streamSettings": { "network": "grpc",
                        "grpcSettings": { "serviceName": "svc", "authority": "", "mode": false },
                        "security": "reality",
                        "realitySettings": { "serverName": "www.example.org", "publicKey": PBK,
                            "shortId": "e347493990237143", "fingerprint": "firefox" } }
                }]
            }
        ])
        .to_string()
    }

    #[test]
    fn configs_become_servers() {
        let s = servers(&sample());
        assert_eq!(s.len(), 4);

        assert_eq!(s[0].name, "🇩🇪 Франкфурт ⚡");
        assert_eq!(s[0].address, "de.example.com");
        assert_eq!(s[0].port, 8443);
        let Security::Reality(r) = &s[0].security else {
            panic!()
        };
        assert_eq!(r.fingerprint, Fingerprint::Qq);
        assert_eq!(r.short_id, "2356d1ae4b");

        assert_eq!(
            s[1].transport,
            Transport::Ws {
                path: "/a b?x=1".into(),
                host: Some("cdn.example.com".into())
            }
        );
        let Security::Tls(tls) = &s[1].security else {
            panic!()
        };
        assert_eq!(tls.alpn, vec!["http/1.1"]);

        let Protocol::Hysteria2 { password, .. } = &s[2].protocol else {
            panic!()
        };
        assert_eq!(password.expose(), "p@ss:word");
        assert_eq!(s[2].transport, Transport::Quic);

        assert_eq!(s[3].address, "2001:db8::1");
        assert_eq!(
            s[3].transport,
            Transport::Grpc {
                service_name: "svc".into()
            }
        );
    }

    #[test]
    fn vmess_config_becomes_server() {
        let body = r#"[{"remarks":"VM","outbounds":[{"tag":"proxy","protocol":"vmess",
            "settings":{"vnext":[{"address":"vm.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0,"security":"auto"}]}]},
            "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/vm"},"tlsSettings":{"serverName":"vm.example.com"}}}]}]"#;
        let s = servers(body);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "VM");
        assert!(
            matches!(&s[0].protocol, crate::model::Protocol::Vmess { cipher, .. } if cipher == "auto")
        );
        assert!(matches!(&s[0].security, Security::Tls(_)));
    }

    #[test]
    fn whole_body_goes_through_subscription_parser() {
        let c = super::super::parse_subscription_body(&sample());
        assert_eq!(c.servers.len(), 4);
        assert!(c.errors.is_empty(), "{:?}", c.errors);
    }

    /// Ручная группа: JSON и ссылки — разные вставки, ни одна не теряет серверов.
    #[test]
    fn json_and_links_pasted_separately() {
        let sep = super::super::CHUNK_SEPARATOR;
        let link = "trojan://pass@t.example.com:443?sni=t.example.com#T";
        for body in [
            format!("{}\n{sep}\n{link}", sample()),
            format!("{link}\n{sep}\n{}", sample()),
        ] {
            let c = super::super::parse_subscription_body(&body);
            assert_eq!(c.servers.len(), 5, "{:?}", c.errors);
            assert!(c.errors.is_empty(), "{:?}", c.errors);
        }
    }

    /// JSON во вставке становится ссылками с теми же серверами.
    #[test]
    fn pasted_json_becomes_links() {
        let links = super::super::normalize_pasted(&sample());
        assert!(!links.contains('{'));
        assert_eq!(links.lines().count(), 4);
        assert_eq!(
            super::super::parse_subscription_body(&links).servers,
            servers(&sample())
        );
    }

    /// Удаление одного сервера из ручной группы: остальные на месте.
    #[test]
    fn one_server_is_removed_from_manual_group() {
        let sep = super::super::CHUNK_SEPARATOR;
        let link = "trojan://pass@t.example.com:443?sni=t.example.com#T";
        let body = format!(
            "{}\n{sep}\n{link}",
            super::super::normalize_pasted(&sample())
        );
        let all = servers(&sample());

        let without_de = super::super::remove_server(&body, &all[0]).unwrap();
        let left = super::super::parse_subscription_body(&without_de).servers;
        assert_eq!(left.len(), 4);
        assert!(!left.contains(&all[0]));

        let trojan = super::super::parse_subscription_body(link)
            .servers
            .remove(0);
        let without_trojan = super::super::remove_server(&without_de, &trojan).unwrap();
        assert!(!without_trojan.contains(sep), "пустой кусок выброшен");
        assert_eq!(
            super::super::parse_subscription_body(&without_trojan)
                .servers
                .len(),
            3
        );
        // Того, чего нет, не удалить.
        assert!(super::super::remove_server(&without_trojan, &trojan).is_none());
    }

    #[test]
    fn provider_tuning_is_carried_over() {
        let body = serde_json::json!([
            {
                "remarks": "finalmask",
                "outbounds": [{
                    "tag": "proxy", "protocol": "vless",
                    "settings": { "vnext": [{ "address": "a.example.com", "port": 443,
                        "users": [{ "id": ID, "encryption": "none" }] }] },
                    "streamSettings": { "network": "xhttp",
                        "xhttpSettings": { "path": "/x", "mode": "auto",
                            "xPaddingBytes": "100-1000", "xmux": { "maxConcurrency": "16-32" } },
                        "security": "tls", "tlsSettings": { "serverName": "a.example.com" },
                        "finalmask": { "tcp": [{ "type": "fragment",
                            "settings": { "packets": "tlshello", "length": "100-200", "delay": "10-20" } }] } }
                }]
            },
            {
                "remarks": "dialerProxy",
                "outbounds": [
                    {
                        "tag": "proxy", "protocol": "vless",
                        "settings": { "vnext": [{ "address": "b.example.com", "port": 443,
                            "users": [{ "id": ID, "encryption": "none" }] }] },
                        "streamSettings": { "network": "ws", "wsSettings": { "path": "/w" },
                            "security": "tls", "tlsSettings": { "serverName": "b.example.com" },
                            "sockopt": { "dialerProxy": "frag" } },
                        "mux": { "enabled": true, "concurrency": 4 }
                    },
                    { "tag": "frag", "protocol": "freedom",
                      "settings": { "fragment": { "packets": "1-3", "length": 50, "interval": "5-10" } } }
                ]
            },
            {
                "remarks": "негодная фрагментация",
                "outbounds": [{
                    "tag": "proxy", "protocol": "trojan",
                    "settings": { "servers": [{ "address": "c.example.com", "port": 443, "password": "p" }] },
                    "streamSettings": { "security": "tls",
                        "finalmask": { "tcp": [{ "type": "fragment", "settings": { "length": "0" } }] } },
                    "mux": { "enabled": true, "concurrency": -1 }
                }]
            }
        ])
        .to_string();
        let s = servers(&body);
        assert_eq!(s.len(), 3);

        let Transport::Xhttp {
            extra: Some(extra),
            mode,
            ..
        } = &s[0].transport
        else {
            panic!("ожидался XHTTP с extra")
        };
        assert_eq!(mode.as_deref(), Some("auto"));
        let extra: serde_json::Value = serde_json::from_str(extra).unwrap();
        assert_eq!(extra["xPaddingBytes"], "100-1000");
        assert_eq!(extra["xmux"]["maxConcurrency"], "16-32");
        assert!(extra.get("path").is_none());
        let f = s[0].fragment.as_ref().unwrap();
        assert_eq!(
            (f.packets.as_str(), f.delay.as_str()),
            ("tlshello", "10-20")
        );

        let f = s[1].fragment.as_ref().unwrap();
        assert_eq!(
            (f.packets.as_str(), f.length.as_str(), f.delay.as_str()),
            ("1-3", "50", "5-10")
        );
        assert_eq!(s[1].mux, Some(4));

        // Сервер остаётся, негодные настройки — нет.
        assert!(s[2].fragment.is_none() && s[2].mux.is_none());
    }

    #[test]
    fn not_xray_json_is_none() {
        assert!(parse("[1, 2]").is_none());
        assert!(parse("{\"proxies\": []}").is_none());
        assert!(parse("vless://x").is_none());
    }

    #[test]
    fn config_without_supported_outbound_is_an_error() {
        let r = parse(r#"[{"remarks":"x","outbounds":[{"protocol":"wireguard"}]}]"#).unwrap();
        assert!(matches!(r.as_slice(), [Err(ParseError::Unsupported(_))]));
    }
}
