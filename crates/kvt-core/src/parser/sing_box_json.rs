//! Подписка или конфиг sing-box: объект с массивом `outbounds`, у каждого подключения
//! `type`, `tag`, `server`, `server_port`, `tls`, `transport`. Так отвечают панели
//! клиентам sing-box (SFA/SFI, Hiddify Next, Karing), такой же JSON экспортирует
//! Hiddify. Каждое поддерживаемое подключение переводится в обычную ссылку, которую
//! проверяют те же парсеры, что и ссылки из подписки.
//!
//! Служебные подключения (`direct`, `block`, `dns`, `selector`, `urltest`) пропускаются
//! молча; правила маршрутизации, DNS и `endpoints` провайдера не переносятся.

use super::xray_json::encode;
use super::{parse_uri, Entry, ParseError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use url::form_urlencoded::Serializer;

/// Больше подключений не разбираем — та же защита, что и лимит строк.
const MAX_OUTBOUNDS: usize = 10_000;

/// Служебные подключения sing-box — не серверы.
const SERVICE_TYPES: [&str; 6] = ["direct", "block", "dns", "selector", "urltest", "tor"];

/// `None` — это не конфиг sing-box (не JSON, нет `outbounds` или это конфиг Xray с
/// `protocol` у подключений). Иначе по записи на каждое подключение-сервер.
pub(super) fn parse(text: &str) -> Option<Vec<Result<Entry, ParseError>>> {
    Some(
        links(text)?
            .into_iter()
            .map(|uri| parse_uri(&uri?))
            .collect(),
    )
}

/// Те же подключения как ссылки `scheme://…#name`.
pub(super) fn links(text: &str) -> Option<Vec<Result<String, ParseError>>> {
    let root: Value = serde_json::from_str(text).ok()?;
    let outbounds = root.get("outbounds")?.as_array()?;
    // Xray помечает подключения полем `protocol`, sing-box — `type`.
    let is_sing_box = outbounds.iter().any(|o| str_at(o, "type").is_some())
        && !outbounds.iter().any(|o| o.get("protocol").is_some());
    if !is_sing_box {
        return None;
    }
    Some(
        outbounds
            .iter()
            .filter(|o| str_at(o, "type").is_some_and(|t| !SERVICE_TYPES.contains(&t)))
            .take(MAX_OUTBOUNDS)
            .map(outbound_uri)
            .collect(),
    )
}

fn outbound_uri(o: &Value) -> Result<String, ParseError> {
    let kind = str_at(o, "type").unwrap_or_default();
    let host = host(o)?;
    let port = o["server_port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .ok_or(ParseError::MissingField(crate::i18n::tr("порт", "port")))?;
    let name = str_at(o, "tag").unwrap_or_default();
    let mut q = Serializer::new(String::new());

    let (scheme, userinfo) = match kind {
        "vless" => {
            if let Some(flow) = str_at(o, "flow").filter(|f| !f.is_empty()) {
                q.append_pair("flow", flow);
            }
            q.append_pair("encryption", "none");
            ("vless", encode(required(o, "uuid")?))
        }
        "vmess" => {
            if o["alter_id"].as_u64().is_some_and(|a| a > 0) {
                return Err(ParseError::Unsupported(crate::i18n::tr(
                    "VMess с alterId (устаревший вариант)",
                    "VMess with alterId (legacy)",
                )));
            }
            if let Some(cipher) = str_at(o, "security") {
                q.append_pair("encryption", cipher);
            }
            ("vmess", encode(required(o, "uuid")?))
        }
        "trojan" => ("trojan", encode(required(o, "password")?)),
        "shadowsocks" => {
            if str_at(o, "plugin").is_some_and(|p| !p.is_empty()) {
                return Err(ParseError::Unsupported(crate::i18n::tr(
                    "Shadowsocks с плагином",
                    "Shadowsocks with a plugin",
                )));
            }
            let method = required(o, "method")?;
            let password = required(o, "password")?;
            // У Shadowsocks в ссылке только адрес и ключ.
            let userinfo = URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
            return Ok(format!("ss://{userinfo}@{host}:{port}#{}", encode(name)));
        }
        "hysteria2" => return hysteria2_uri(o, &host, port, name),
        "tuic" => {
            let uuid = required(o, "uuid")?;
            let password = required(o, "password")?;
            for (from, to) in [
                ("congestion_control", "congestion_control"),
                ("udp_relay_mode", "udp_relay_mode"),
            ] {
                if let Some(v) = str_at(o, from) {
                    q.append_pair(to, v);
                }
            }
            tls_query(&o["tls"], &mut q, false);
            return Ok(format!(
                "tuic://{}:{}@{host}:{port}?{}#{}",
                encode(uuid),
                encode(password),
                q.finish(),
                encode(name)
            ));
        }
        "anytls" => ("anytls", encode(required(o, "password")?)),
        "socks" => {
            if str_at(o, "version").is_some_and(|v| v != "5") {
                return Err(ParseError::Unsupported("SOCKS4"));
            }
            let auth = match (str_at(o, "username"), str_at(o, "password")) {
                (Some(u), Some(p)) => format!("{}:{}@", encode(u), encode(p)),
                (Some(u), None) => format!("{}@", encode(u)),
                _ => String::new(),
            };
            return Ok(format!("socks5://{auth}{host}:{port}#{}", encode(name)));
        }
        "wireguard" => return Err(ParseError::Unsupported("WireGuard")),
        "hysteria" => {
            return Err(ParseError::Unsupported(crate::i18n::tr(
                "Hysteria первой версии",
                "Hysteria v1",
            )))
        }
        "shadowtls" => return Err(ParseError::Unsupported("ShadowTLS")),
        "naive" => return Err(ParseError::Unsupported("NaiveProxy")),
        "ssh" => return Err(ParseError::Unsupported("SSH")),
        "http" => {
            // Прокси без логина ссылкой не отличить от адреса сайта — не берём.
            let user = required(o, "username").map_err(|_| {
                ParseError::Unsupported(crate::i18n::tr(
                    "HTTP-прокси без логина",
                    "HTTP proxy without a login",
                ))
            })?;
            let auth = match str_at(o, "password") {
                Some(p) => format!("{}:{}@", encode(user), encode(p)),
                None => format!("{}@", encode(user)),
            };
            let tls = o["tls"]["enabled"].as_bool() == Some(true);
            if tls {
                tls_query(&o["tls"], &mut q, false);
            }
            if o["tls"]["reality"]["enabled"].as_bool() == Some(true) {
                return Err(ParseError::Unsupported(crate::i18n::tr(
                    "HTTP-прокси с REALITY",
                    "HTTP proxy with REALITY",
                )));
            }
            let query = q.finish();
            return Ok(format!(
                "{}://{auth}{host}:{port}/{}{}#{}",
                if tls { "https" } else { "http" },
                if query.is_empty() { "" } else { "?" },
                query,
                encode(name)
            ));
        }
        _ => {
            return Err(ParseError::Unsupported(crate::i18n::tr(
                "тип подключения",
                "connection type",
            )))
        }
    };

    transport_query(&o["transport"], &mut q);
    tls_query(&o["tls"], &mut q, true);
    Ok(format!(
        "{scheme}://{userinfo}@{host}:{port}?{}#{}",
        q.finish(),
        encode(name)
    ))
}

fn hysteria2_uri(o: &Value, host: &str, port: u16, name: &str) -> Result<String, ParseError> {
    let password = required(o, "password")?;
    let mut q = Serializer::new(String::new());
    let obfs = &o["obfs"];
    if let Some(kind) = str_at(obfs, "type") {
        q.append_pair("obfs", kind);
        if let Some(p) = str_at(obfs, "password") {
            q.append_pair("obfs-password", p);
        }
    }
    // `server_ports: ["20000:30000"]` → `mport=20000-30000`.
    if let Some(ranges) = o["server_ports"].as_array() {
        let list: Vec<String> = ranges
            .iter()
            .filter_map(Value::as_str)
            .map(|r| r.replace(':', "-"))
            .collect();
        if !list.is_empty() {
            q.append_pair("mport", &list.join(","));
        }
    }
    tls_query(&o["tls"], &mut q, false);
    Ok(format!(
        "hysteria2://{}@{host}:{port}?{}#{}",
        encode(password),
        q.finish(),
        encode(name)
    ))
}

/// `transport` → `type`, `path`, `host`, `serviceName`.
fn transport_query(t: &Value, q: &mut Serializer<'_, String>) {
    let kind = str_at(t, "type").unwrap_or("tcp");
    q.append_pair("type", kind);
    if let Some(path) = str_at(t, "path") {
        q.append_pair("path", path);
    }
    // `headers.Host` бывает строкой или списком; у httpupgrade — поле `host`.
    let host = str_at(t, "host")
        .or_else(|| str_at(&t["headers"], "Host"))
        .or_else(|| t["headers"]["Host"][0].as_str())
        .or_else(|| t["host"][0].as_str());
    if let Some(host) = host.filter(|h| !h.is_empty()) {
        q.append_pair("host", host);
    }
    if let Some(service) = str_at(t, "service_name") {
        q.append_pair("serviceName", service);
    }
}

/// `tls` → `security`, `sni`, `alpn`, `fp`, `pbk`, `sid`, `insecure`. `with_security` —
/// писать ли `security` (у Hysteria2 и TUIC TLS всегда, параметра нет).
fn tls_query(tls: &Value, q: &mut Serializer<'_, String>, with_security: bool) {
    let enabled = tls["enabled"].as_bool() == Some(true);
    let reality = &tls["reality"];
    let is_reality = enabled && reality["enabled"].as_bool() == Some(true);
    if with_security {
        q.append_pair(
            "security",
            match (enabled, is_reality) {
                (_, true) => "reality",
                (true, false) => "tls",
                _ => "none",
            },
        );
    }
    if !enabled {
        return;
    }
    if let Some(sni) = str_at(tls, "server_name").filter(|s| !s.is_empty()) {
        q.append_pair("sni", sni);
    }
    if let Some(alpn) = tls["alpn"].as_array() {
        let list: Vec<&str> = alpn.iter().filter_map(Value::as_str).collect();
        if !list.is_empty() {
            q.append_pair("alpn", &list.join(","));
        }
    }
    let utls = &tls["utls"];
    if utls["enabled"].as_bool() != Some(false) {
        if let Some(fp) = str_at(utls, "fingerprint") {
            q.append_pair("fp", fp);
        }
    }
    if is_reality {
        if let Some(pbk) = str_at(reality, "public_key") {
            q.append_pair("pbk", pbk);
        }
        if let Some(sid) = str_at(reality, "short_id") {
            q.append_pair("sid", sid);
        }
    }
    if tls["insecure"].as_bool() == Some(true) {
        q.append_pair("insecure", "1");
    }
    let ech = &tls["ech"];
    if ech["enabled"].as_bool() == Some(true) {
        // PEM из строк массива → base64 ECHConfigList. Без готового конфига (его
        // ищут DNS-запросом) — значение, которое разбор отвергнет с причиной: иначе
        // сервер подключился бы без ECH молча.
        let config: String = ech["config"]
            .as_array()
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(Value::as_str)
                    .flat_map(str::lines)
                    .filter(|l| !l.starts_with("-----"))
                    .map(str::trim)
                    .collect()
            })
            .unwrap_or_default();
        // «:» в base64 не бывает — разбор ответит «ECH с запросом конфига через DNS».
        q.append_pair(
            "ech",
            if config.is_empty() {
                "dns:query"
            } else {
                &config
            },
        );
    }
}

fn host(o: &Value) -> Result<String, ParseError> {
    let address = required(o, "server")?;
    // IPv6 в ссылке — в квадратных скобках.
    Ok(if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]")
    } else {
        address.to_owned()
    })
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn required<'a>(v: &'a Value, key: &'static str) -> Result<&'a str, ParseError> {
    str_at(v, key)
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::MissingField(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Fingerprint, Protocol, Security, Server, Transport};

    const ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const PBK: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

    fn sample() -> String {
        serde_json::json!({
            "log": { "level": "warn" },
            "outbounds": [
                { "type": "selector", "tag": "proxy", "outbounds": ["🇩🇪 Германия", "🇳🇱 hy2"] },
                {
                    "type": "vless", "tag": "🇩🇪 Германия", "server": "de.example.com", "server_port": 443,
                    "uuid": ID, "flow": "xtls-rprx-vision",
                    "tls": { "enabled": true, "server_name": "www.example.org",
                        "utls": { "enabled": true, "fingerprint": "firefox" },
                        "reality": { "enabled": true, "public_key": PBK, "short_id": "2356d1ae4b" } }
                },
                {
                    "type": "hysteria2", "tag": "🇳🇱 hy2", "server": "nl.example.com", "server_port": 443,
                    "server_ports": ["20000:30000"], "password": "p@ss",
                    "obfs": { "type": "salamander", "password": "o" },
                    "tls": { "enabled": true, "server_name": "nl.example.com" }
                },
                {
                    "type": "trojan", "tag": "ws", "server": "2001:db8::1", "server_port": 8443,
                    "password": "t", "transport": { "type": "ws", "path": "/ws", "headers": { "Host": "cdn.example.com" } },
                    "tls": { "enabled": true, "server_name": "cdn.example.com", "insecure": true }
                },
                {
                    "type": "tuic", "tag": "tuic", "server": "tu.example.com", "server_port": 443,
                    "uuid": ID, "password": "x", "congestion_control": "bbr",
                    "tls": { "enabled": true, "server_name": "tu.example.com", "alpn": ["h3"] }
                },
                { "type": "shadowsocks", "tag": "ss", "server": "ss.example.com", "server_port": 8388,
                  "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==" },
                { "type": "socks", "tag": "s5", "server": "px.example.com", "server_port": 1080,
                  "username": "u", "password": "p" },
                { "type": "wireguard", "tag": "wg", "server": "wg.example.com", "server_port": 51820 },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": { "final": "proxy" }
        })
        .to_string()
    }

    fn servers(text: &str) -> Vec<Result<Server, ParseError>> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|e| {
                e.map(|e| match e {
                    Entry::Server(s) => *s,
                    Entry::Info(i) => panic!("служебная запись {i}"),
                })
            })
            .collect()
    }

    #[test]
    fn every_supported_outbound_becomes_server() {
        let got = servers(&sample());
        // selector, direct и block пропущены молча, WireGuard — с причиной.
        assert_eq!(got.len(), 7);
        assert_eq!(got[6], Err(ParseError::Unsupported("WireGuard")));

        let vless = got[0].as_ref().unwrap();
        assert_eq!(vless.name, "🇩🇪 Германия");
        assert_eq!(vless.port, 443);
        let Security::Reality(r) = &vless.security else {
            panic!("ожидался REALITY")
        };
        assert_eq!(
            (r.sni.as_str(), r.fingerprint),
            ("www.example.org", Fingerprint::Firefox)
        );
        assert_eq!(r.short_id, "2356d1ae4b");

        let hy2 = got[1].as_ref().unwrap();
        let Protocol::Hysteria2 {
            password,
            obfs,
            ports,
            ..
        } = &hy2.protocol
        else {
            panic!("ожидался Hysteria2")
        };
        assert_eq!(password.expose(), "p@ss");
        assert!(obfs.is_some());
        assert_eq!(ports.as_deref(), Some("20000-30000"));

        let trojan = got[2].as_ref().unwrap();
        assert_eq!(trojan.address, "2001:db8::1");
        assert!(
            matches!(&trojan.transport, Transport::Ws { path, host } if path == "/ws" && host.as_deref() == Some("cdn.example.com"))
        );
        assert!(matches!(&trojan.security, Security::Tls(t) if t.allow_insecure));

        assert!(matches!(
            got[3].as_ref().unwrap().protocol,
            Protocol::Tuic { .. }
        ));
        assert!(matches!(
            got[4].as_ref().unwrap().protocol,
            Protocol::Shadowsocks { .. }
        ));
        assert!(matches!(
            got[5].as_ref().unwrap().protocol,
            Protocol::Socks { .. }
        ));
    }

    #[test]
    fn ech_config_survives_dns_query_is_refused() {
        let ech = "AEX+DQBBpQAgACB/qtKXQOgnyY4kyw6jZ3Zt0ZNy1PtoE6OdBMsyqF4tPQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";
        let text = serde_json::json!({ "outbounds": [
            { "type": "trojan", "tag": "a", "server": "t.example.com", "server_port": 443, "password": "p",
              "tls": { "enabled": true, "server_name": "t.example.com",
                "ech": { "enabled": true, "config": ["-----BEGIN ECH CONFIGS-----", ech, "-----END ECH CONFIGS-----"] } } },
            { "type": "trojan", "tag": "b", "server": "t.example.com", "server_port": 443, "password": "p",
              "tls": { "enabled": true, "server_name": "t.example.com", "ech": { "enabled": true } } }
        ]})
        .to_string();
        let got = servers(&text);
        let Security::Tls(tls) = &got[0].as_ref().unwrap().security else {
            panic!("ожидался TLS")
        };
        assert_eq!(tls.ech.as_deref(), Some(ech));
        assert_eq!(
            got[1],
            Err(ParseError::Unsupported("ECH с запросом конфига через DNS"))
        );
    }

    #[test]
    fn http_proxy_outbounds() {
        let text = serde_json::json!({ "outbounds": [
            { "type": "http", "tag": "h", "server": "px.example.com", "server_port": 8080,
              "username": "u", "password": "p@ss" },
            { "type": "http", "tag": "hs", "server": "px.example.com", "server_port": 8443,
              "username": "u", "password": "p",
              "tls": { "enabled": true, "server_name": "front.example.com" } },
            { "type": "http", "tag": "open", "server": "px.example.com", "server_port": 3128 }
        ]})
        .to_string();
        let got = servers(&text);
        let plain = got[0].as_ref().unwrap();
        assert!(matches!(plain.protocol, Protocol::Http { .. }));
        assert_eq!((plain.port, &plain.security), (8080, &Security::None));
        assert_eq!(plain.name, "h");
        let tls = got[1].as_ref().unwrap();
        let Security::Tls(t) = &tls.security else {
            panic!("ожидался TLS")
        };
        assert_eq!(t.sni.as_deref(), Some("front.example.com"));
        assert_eq!(
            got[2],
            Err(ParseError::Unsupported("HTTP-прокси без логина"))
        );
    }

    #[test]
    fn xray_config_is_not_taken() {
        let xray = r#"{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"vless","tag":"proxy"}]}"#;
        assert!(links(xray).is_none());
        assert!(links("not json").is_none());
        assert!(links(r#"{"inbounds":[]}"#).is_none());
    }

    #[test]
    fn trojan_without_tls_stays_without_tls() {
        let text = r#"{"outbounds":[{"type":"trojan","tag":"t","server":"h.example.com","server_port":80,"password":"p"}]}"#;
        let got = servers(text);
        assert!(matches!(got[0].as_ref().unwrap().security, Security::None));
    }

    #[test]
    fn broken_outbounds_give_errors_not_panics() {
        let text = r#"{"outbounds":[
            {"type":"vless"},
            {"type":"vless","server":"h","server_port":99999,"uuid":"x"},
            {"type":"vless","server":"h","server_port":443},
            {"type":"vmess","server":"h","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alter_id":64},
            {"type":"shadowsocks","server":"h","server_port":1,"method":"aes-128-gcm","password":"p","plugin":"obfs-local"},
            {"type":42}
        ]}"#;
        assert!(servers(text).iter().all(Result::is_err));
    }

    #[test]
    fn whole_body_goes_through_subscription_parser() {
        let content = crate::parser::parse_subscription_body(&sample());
        assert_eq!(content.servers.len(), 6);
        assert_eq!(content.errors.len(), 1);
        // Вставка в группу «Добавлено вручную» — ссылками, по одной на строку.
        let pasted = crate::parser::normalize_pasted(&sample());
        assert_eq!(pasted.lines().count(), 6);
        assert!(pasted.lines().all(|l| l.contains("://")));
    }
}
