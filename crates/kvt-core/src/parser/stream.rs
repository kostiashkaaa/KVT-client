//! Общие параметры транспорта и шифрования для VLESS/Trojan-ссылок
//! (`type`, `security`, `sni`, `fp`, `pbk`, `sid`, `path`, `host`, ...).

use super::{decode_base64_lenient, ParseError};
use crate::model::{Fingerprint, RealitySettings, Security, TlsSettings, Transport};
use std::collections::HashMap;

type Query = HashMap<String, String>;

fn non_empty(q: &Query, key: &str) -> Option<String> {
    q.get(key)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

pub(crate) fn parse_transport(q: &Query) -> Result<Transport, ParseError> {
    let kind = non_empty(q, "type")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    let path = || non_empty(q, "path").unwrap_or_else(|| "/".into());
    let host = || non_empty(q, "host");

    Ok(match kind.as_str() {
        "tcp" | "raw" => {
            if non_empty(q, "headertype").is_some_and(|h| h != "none") {
                return Err(ParseError::Unsupported(crate::i18n::tr(
                    "TCP с HTTP-заголовками",
                    "TCP with HTTP headers",
                )));
            }
            Transport::Tcp
        }
        "ws" => Transport::Ws {
            path: path(),
            host: host(),
        },
        "grpc" => Transport::Grpc {
            service_name: non_empty(q, "servicename").unwrap_or_default(),
        },
        "httpupgrade" => Transport::HttpUpgrade {
            path: path(),
            host: host(),
        },
        "xhttp" | "splithttp" => Transport::Xhttp {
            path: path(),
            host: host(),
            mode: non_empty(q, "mode"),
        },
        _ => {
            return Err(ParseError::Unsupported(crate::i18n::tr(
                "транспорт",
                "transport",
            )))
        }
    })
}

pub(crate) fn parse_security(q: &Query, default_security: &str) -> Result<Security, ParseError> {
    let kind = non_empty(q, "security")
        .unwrap_or_else(|| default_security.into())
        .to_ascii_lowercase();
    let fingerprint = match non_empty(q, "fp") {
        Some(fp) => Some(Fingerprint::parse(&fp).ok_or(ParseError::InvalidField {
            field: "fp",
            reason: crate::i18n::tr("неизвестный отпечаток", "unknown fingerprint"),
        })?),
        None => None,
    };

    Ok(match kind.as_str() {
        "none" | "" => Security::None,
        "tls" => Security::Tls(TlsSettings {
            sni: non_empty(q, "sni").or_else(|| non_empty(q, "peer")),
            alpn: non_empty(q, "alpn")
                .map(|a| {
                    a.split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            fingerprint,
            allow_insecure: is_truthy(q, "allowinsecure") || is_truthy(q, "insecure"),
            ech: parse_ech(q)?,
        }),
        "reality" => {
            let sni = non_empty(q, "sni").ok_or(ParseError::MissingField("sni"))?;
            let public_key = non_empty(q, "pbk").ok_or(ParseError::MissingField("pbk"))?;
            validate_reality_key(&public_key)?;
            let short_id = non_empty(q, "sid").unwrap_or_default();
            validate_short_id(&short_id)?;
            Security::Reality(RealitySettings {
                sni,
                public_key,
                short_id,
                // В REALITY отпечаток обязателен; если провайдер его не указал,
                // берём Firefox — он реже вызывает подозрения у ТСПУ.
                fingerprint: fingerprint.unwrap_or(Fingerprint::Firefox),
                spider_x: non_empty(q, "spx"),
            })
        }
        _ => {
            return Err(ParseError::Unsupported(crate::i18n::tr(
                "тип шифрования",
                "security type",
            )))
        }
    })
}

/// Самый длинный ECHConfigList, который принимаем (у Cloudflare — около 70 байт).
const MAX_ECH_BYTES: usize = 4096;

/// Параметр `ech`: готовый ECHConfigList в base64. Вариант «имя+DoH» (конфиг
/// узнаётся DNS-запросом при подключении) ядра в этом виде не принимают — сервер
/// пропускается с причиной, а не подключается без ECH молча.
pub(crate) fn parse_ech(q: &Query) -> Result<Option<String>, ParseError> {
    let Some(value) = non_empty(q, "ech") else {
        return Ok(None);
    };
    let bytes = decode_base64_lenient(&value).ok_or(ParseError::Unsupported(crate::i18n::tr(
        "ECH с запросом конфига через DNS",
        "ECH with config fetched over DNS",
    )))?;
    // ECHConfigList начинается с длины остатка (2 байта).
    let declared = bytes
        .get(..2)
        .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])));
    if bytes.len() < 4 || bytes.len() > MAX_ECH_BYTES || declared != Some(bytes.len() - 2) {
        return Err(ParseError::InvalidField {
            field: "ech",
            reason: crate::i18n::tr("не похоже на конфиг ECH", "doesn't look like an ECH config"),
        });
    }
    use base64::Engine as _;
    Ok(Some(
        base64::engine::general_purpose::STANDARD.encode(bytes),
    ))
}

fn is_truthy(q: &Query, key: &str) -> bool {
    matches!(q.get(key).map(String::as_str), Some("1" | "true"))
}

/// Публичный ключ X25519: 32 байта в base64url.
fn validate_reality_key(key: &str) -> Result<(), ParseError> {
    match decode_base64_lenient(key) {
        Some(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err(ParseError::InvalidField {
            field: "pbk",
            reason: crate::i18n::tr("ожидается ключ X25519", "expected an X25519 key"),
        }),
    }
}

/// shortId: до 16 hex-символов, чётной длины.
fn validate_short_id(sid: &str) -> Result<(), ParseError> {
    let ok = sid.len() <= 16 && sid.len() % 2 == 0 && sid.chars().all(|c| c.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(ParseError::InvalidField {
            field: "sid",
            reason: crate::i18n::tr(
                "ожидается hex до 16 символов",
                "expected hex up to 16 characters",
            ),
        })
    }
}
