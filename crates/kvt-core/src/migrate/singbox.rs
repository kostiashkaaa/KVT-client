//! sing-box: исходящие Throne (таблица `profiles`) и локальные профили Hiddify → ссылки.

use super::link::{enc, number, object, ss_user, text, truthy, Link};
use super::Collected;
use crate::i18n::tr;
use serde_json::{Map, Value};

/// Типы исходящих sing-box, которые не являются серверами (их молча пропускаем).
pub fn is_service_outbound(v: &Value) -> bool {
    matches!(
        v.get("type").and_then(Value::as_str),
        Some("direct" | "block" | "dns" | "selector" | "urltest")
    )
}

/// Исходящее sing-box (`{"type": "vless", "server": ..., "tls": {...}}`).
pub fn singbox_outbound(v: &Value, name: &str) -> Result<String, &'static str> {
    let o = v.as_object().ok_or(tr(
        "неполные или повреждённые данные сервера",
        "incomplete or broken server data",
    ))?;
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
            _ => {
                return Err(tr(
                    "протокол или настройка не поддерживается",
                    "protocol or setting not supported",
                ))
            }
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
                return Err(tr(
                    "плагины Shadowsocks не поддерживаются",
                    "Shadowsocks plugins are not supported",
                ));
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
        "vmess" => return Err(tr("VMess не поддерживается", "VMess is not supported")),
        _ => {
            return Err(tr(
                "протокол или настройка не поддерживается",
                "protocol or setting not supported",
            ))
        }
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
