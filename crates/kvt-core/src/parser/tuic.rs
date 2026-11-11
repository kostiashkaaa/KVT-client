//! TUIC v5: `tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=…#имя`.
//! Работает поверх QUIC, поэтому только через sing-box.

use super::{decode_component, host_of, name_of, parse_url, port_of, query_of, ParseError};
use crate::model::{Protocol, Security, Server, TlsSettings, Transport};
use crate::secret::Secret;

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let url = parse_url(input)?;
    let uuid = decode_component(url.username());
    if uuid::Uuid::parse_str(&uuid).is_err() {
        return Err(ParseError::InvalidField {
            field: "uuid",
            reason: crate::i18n::tr("не UUID", "not a UUID"),
        });
    }
    let password = url.password().map(decode_component).unwrap_or_default();
    if password.is_empty() {
        return Err(ParseError::MissingField(crate::i18n::tr(
            "пароль",
            "password",
        )));
    }
    let address = host_of(&url)?;
    let port = port_of(&url)?;
    let q = query_of(&url);
    let get = |k: &str| {
        q.get(k)
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
    };

    let congestion = get("congestion_control").or_else(|| get("congestion"));
    if congestion
        .as_deref()
        .is_some_and(|c| !matches!(c, "cubic" | "new_reno" | "bbr"))
    {
        return Err(ParseError::Unsupported(crate::i18n::tr(
            "алгоритм перегрузки TUIC",
            "TUIC congestion algorithm",
        )));
    }
    let udp_relay_mode = get("udp_relay_mode");
    if udp_relay_mode
        .as_deref()
        .is_some_and(|m| !matches!(m, "native" | "quic"))
    {
        return Err(ParseError::Unsupported(crate::i18n::tr(
            "режим UDP TUIC",
            "TUIC UDP mode",
        )));
    }
    let alpn: Vec<String> = get("alpn")
        .map(|a| {
            a.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|| vec!["h3".into()]);
    let insecure = ["allow_insecure", "allowinsecure", "insecure"]
        .iter()
        .any(|k| matches!(get(k).as_deref(), Some("1" | "true")));

    Ok(Server {
        name: name_of(&url, &address),
        protocol: Protocol::Tuic {
            uuid: Secret::new(uuid),
            password: Secret::new(password),
            congestion,
            udp_relay_mode,
        },
        transport: Transport::Quic,
        security: Security::Tls(TlsSettings {
            sni: q
                .get("sni")
                .or_else(|| q.get("peer"))
                .filter(|s| !s.is_empty())
                .cloned(),
            alpn,
            fingerprint: None,
            allow_insecure: insecure,
            ech: super::stream::parse_ech(&q)?,
        }),
        address,
        port,
        fragment: None,
        mux: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typical_link() {
        let s = parse("tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pa%40ss@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=t.example.com#TUIC").unwrap();
        assert_eq!(s.name, "TUIC");
        assert!(s.protocol.is_quic());
        let Protocol::Tuic {
            password,
            congestion,
            ..
        } = &s.protocol
        else {
            panic!("ожидался TUIC")
        };
        assert_eq!(password.expose(), "pa@ss");
        assert_eq!(congestion.as_deref(), Some("bbr"));
        assert!(matches!(&s.security, Security::Tls(t) if t.alpn == ["h3"] && !t.allow_insecure));
    }

    #[test]
    fn bad_links() {
        assert!(parse("tuic://not-uuid:p@h.example.com:443").is_err());
        assert!(parse("tuic://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443").is_err());
        assert!(parse(
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:p@h.example.com:443?congestion_control=x"
        )
        .is_err());
    }
}
