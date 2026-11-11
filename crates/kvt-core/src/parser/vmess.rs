//! VMess: ссылка v2rayN (`vmess://` + base64 JSON) или в виде URL
//! (`vmess://uuid@host:port?type=ws&security=tls#имя`). Только AEAD: `alterId` больше
//! нуля — устаревший вариант, его не поддерживает и Xray.

use super::stream::{parse_security, parse_transport};
use super::{
    decode_base64_lenient, decode_component, host_of, name_of, parse_url, port_of, query_of,
    ParseError,
};
use crate::model::{Protocol, Server};
use crate::secret::Secret;
use serde_json::Value;
use std::collections::HashMap;

const CIPHERS: &[&str] = &["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"];

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let rest = input
        .split_once("://")
        .map(|(_, r)| r)
        .ok_or(ParseError::InvalidUrl)?;
    // Название может стоять после `#` и у base64-варианта (так переименовывает KVT).
    let (payload, fragment) = match rest.split_once('#') {
        Some((p, f)) => (p, Some(decode_component(f).trim().to_owned())),
        None => (rest, None),
    };
    let fragment = fragment.filter(|f| !f.is_empty());
    let json = decode_base64_lenient(payload)
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .filter(Value::is_object);
    match json {
        Some(v) => from_json(&v, fragment),
        None => from_url(input),
    }
}

fn text(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn cipher(raw: Option<String>) -> Result<String, ParseError> {
    let c = raw.unwrap_or_else(|| "auto".into()).to_ascii_lowercase();
    if CIPHERS.contains(&c.as_str()) {
        Ok(c)
    } else {
        Err(ParseError::Unsupported(crate::i18n::tr(
            "шифр VMess",
            "VMess cipher",
        )))
    }
}

fn check_alter_id(aid: Option<String>) -> Result<(), ParseError> {
    match aid.as_deref().map(str::parse::<u32>) {
        None | Some(Ok(0)) => Ok(()),
        Some(Ok(_)) => Err(ParseError::Unsupported(crate::i18n::tr(
            "VMess с alterId (устаревший вариант)",
            "VMess with alterId (legacy)",
        ))),
        Some(Err(_)) => Err(ParseError::InvalidField {
            field: "aid",
            reason: crate::i18n::tr("не число", "not a number"),
        }),
    }
}

fn check_id(id: &str) -> Result<(), ParseError> {
    if uuid::Uuid::parse_str(id).is_ok() {
        Ok(())
    } else {
        Err(ParseError::InvalidField {
            field: "id",
            reason: crate::i18n::tr("не UUID", "not a UUID"),
        })
    }
}

/// Формат v2rayN: поля JSON переводятся в те же параметры, что у VLESS-ссылок.
fn from_json(v: &Value, fragment: Option<String>) -> Result<Server, ParseError> {
    let address = text(v, "add").ok_or(ParseError::MissingField(crate::i18n::tr(
        "адрес",
        "address",
    )))?;
    let address = address.trim_matches(['[', ']']).to_owned();
    let port: u16 = text(v, "port")
        .ok_or(ParseError::MissingField(crate::i18n::tr("порт", "port")))?
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or(ParseError::InvalidField {
            field: crate::i18n::tr("порт", "port"),
            reason: crate::i18n::tr("не число от 1 до 65535", "not a number from 1 to 65535"),
        })?;
    let id = text(v, "id").ok_or(ParseError::MissingField("id"))?;
    check_id(&id)?;
    check_alter_id(text(v, "aid"))?;

    let mut q: HashMap<String, String> = HashMap::new();
    let mut put = |k: &str, val: Option<String>| {
        if let Some(val) = val {
            q.insert(k.to_owned(), val);
        }
    };
    let net = text(v, "net")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    if net == "grpc" {
        // У gRPC имя сервиса v2rayN кладёт в `path`.
        put("servicename", text(v, "path"));
    } else {
        put("path", text(v, "path"));
    }
    put("type", Some(net));
    put("headertype", text(v, "type"));
    put("host", text(v, "host"));
    put("mode", text(v, "mode"));
    put("security", text(v, "tls"));
    put("sni", text(v, "sni"));
    put("alpn", text(v, "alpn"));
    put("fp", text(v, "fp"));
    put("pbk", text(v, "pbk"));
    put("sid", text(v, "sid"));
    put("spx", text(v, "spx"));
    put("allowinsecure", text(v, "allowInsecure"));

    let name = fragment
        .or_else(|| text(v, "ps"))
        .unwrap_or_else(|| address.clone());
    Ok(Server {
        name,
        protocol: Protocol::Vmess {
            id: Secret::new(id),
            cipher: cipher(text(v, "scy"))?,
        },
        transport: parse_transport(&q)?,
        security: parse_security(&q, "none")?,
        address,
        port,
    })
}

/// URL-вид (sing-box, Shadowrocket): `security` здесь — TLS, шифр — в `encryption`.
fn from_url(input: &str) -> Result<Server, ParseError> {
    let url = parse_url(input)?;
    let id = decode_component(url.username());
    check_id(&id)?;
    let address = host_of(&url)?;
    let port = port_of(&url)?;
    let q = query_of(&url);
    check_alter_id(q.get("alterid").or_else(|| q.get("aid")).cloned())?;
    Ok(Server {
        name: name_of(&url, &address),
        protocol: Protocol::Vmess {
            id: Secret::new(id),
            cipher: cipher(q.get("encryption").cloned())?,
        },
        transport: parse_transport(&q)?,
        security: parse_security(&q, "none")?,
        address,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Security, Transport};
    use base64::Engine;

    const ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn link(json: &str) -> String {
        format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        )
    }

    #[test]
    fn v2rayn_ws_tls() {
        let s = parse(&link(&format!(
            r#"{{"v":"2","ps":"DE ws","add":"de.example.com","port":"443","id":"{ID}","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com","fp":"firefox"}}"#
        )))
        .unwrap();
        assert_eq!(s.name, "DE ws");
        assert_eq!(s.port, 443);
        assert_eq!(
            s.transport,
            Transport::Ws {
                path: "/ws".into(),
                host: Some("cdn.example.com".into())
            }
        );
        assert!(
            matches!(&s.security, Security::Tls(t) if t.sni.as_deref() == Some("cdn.example.com"))
        );
        assert!(matches!(&s.protocol, Protocol::Vmess { cipher, .. } if cipher == "auto"));
    }

    #[test]
    fn numbers_grpc_and_name_after_hash() {
        let s = parse(&format!(
            "{}#{}",
            link(&format!(
                r#"{{"add":"1.2.3.4","port":8443,"id":"{ID}","aid":0,"net":"grpc","path":"svc","tls":""}}"#
            )),
            "%D0%A1%D0%B2%D0%BE%D0%B9"
        ))
        .unwrap();
        assert_eq!(s.name, "Свой");
        assert_eq!(s.port, 8443);
        assert_eq!(
            s.transport,
            Transport::Grpc {
                service_name: "svc".into()
            }
        );
        assert_eq!(s.security, Security::None);
    }

    #[test]
    fn url_form() {
        let s = parse(&format!(
            "vmess://{ID}@v.example.com:443?type=ws&path=%2Fv&security=tls&encryption=aes-128-gcm#URL"
        ))
        .unwrap();
        assert_eq!(s.name, "URL");
        assert!(matches!(&s.protocol, Protocol::Vmess { cipher, .. } if cipher == "aes-128-gcm"));
    }

    #[test]
    fn legacy_and_broken_are_rejected() {
        let aid = link(&format!(
            r#"{{"add":"a.b","port":"1","id":"{ID}","aid":"64"}}"#
        ));
        assert!(matches!(parse(&aid), Err(ParseError::Unsupported(_))));
        let http = link(&format!(
            r#"{{"add":"a.b","port":"1","id":"{ID}","net":"tcp","type":"http"}}"#
        ));
        assert!(matches!(parse(&http), Err(ParseError::Unsupported(_))));
        assert!(parse("vmess://not-base64-and-not-url").is_err());
        let bad_id = link(r#"{"add":"a.b","port":"1","id":"x"}"#);
        assert!(parse(&bad_id).is_err());
    }
}
