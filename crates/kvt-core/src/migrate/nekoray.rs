//! NekoRay и старый Throne: профиль из `config\profiles\*.json` → название и ссылка.

use super::link::{enc, number, object, ss_user, text, truthy, Link};
use crate::i18n::tr;
use serde_json::{Map, Value};

/// Профиль NekoRay: `{"type": "vless", "bean": {...}}`.
pub fn nekoray_profile(v: &Value) -> Result<(String, String), &'static str> {
    let kind = v.get("type").and_then(Value::as_str).unwrap_or_default();
    let bean = v.get("bean").and_then(Value::as_object).ok_or(tr(
        "неполные или повреждённые данные сервера",
        "incomplete or broken server data",
    ))?;
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
                return Err(tr(
                    "плагины Shadowsocks не поддерживаются",
                    "Shadowsocks plugins are not supported",
                ));
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
        "vmess" => return Err(tr("VMess не поддерживается", "VMess is not supported")),
        _ => {
            return Err(tr(
                "протокол или настройка не поддерживается",
                "protocol or setting not supported",
            ))
        }
    }
    Ok((name, link.build()?))
}
