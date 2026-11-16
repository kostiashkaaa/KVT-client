//! v2rayN: строка таблицы `ProfileItem` из `guiConfigs\guiNDB.db` → ссылка.

use super::link::{enc, json_field, number, ss_user, text, truthy, Link};
use crate::i18n::tr;
use serde_json::{Map, Value};

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
        1 => return Err(tr("VMess не поддерживается", "VMess is not supported")),
        _ => {
            return Err(tr(
                "протокол или настройка не поддерживается",
                "protocol or setting not supported",
            ))
        }
    }
    link.build()
}
