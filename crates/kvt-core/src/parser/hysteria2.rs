use super::{decode_component, host_of, name_of, parse_url, port_of, query_of, ParseError};
use crate::model::{Hysteria2Obfs, Protocol, Security, Server, TlsSettings, Transport};
use crate::secret::Secret;

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let url = parse_url(input).map_err(|e| {
        // Диапазон портов (port hopping) в адресе ломает стандартный разбор URL.
        if input
            .split('?')
            .next()
            .is_some_and(|p| p.contains(',') || p.matches('-').count() > 1)
        {
            ParseError::Unsupported("Hysteria2 с диапазоном портов")
        } else {
            e
        }
    })?;
    // `hy2://user:pass@` — пароль собирается обратно целиком.
    let password = match url.password() {
        Some(p) => format!(
            "{}:{}",
            decode_component(url.username()),
            decode_component(p)
        ),
        None => decode_component(url.username()),
    };
    if password.is_empty() {
        return Err(ParseError::MissingField("пароль"));
    }
    let address = host_of(&url)?;
    let q = query_of(&url);

    let obfs = match q.get("obfs").map(String::as_str) {
        None | Some("") | Some("none") => None,
        Some("salamander") => Some(Hysteria2Obfs {
            kind: "salamander".into(),
            password: Secret::new(
                q.get("obfs-password")
                    .cloned()
                    .ok_or(ParseError::MissingField("obfs-password"))?,
            ),
        }),
        Some(_) => return Err(ParseError::Unsupported("obfs")),
    };

    Ok(Server {
        name: name_of(&url, &address),
        port: port_of(&url).or_else(|e| match e {
            ParseError::MissingField(_) => Ok(443),
            other => Err(other),
        })?,
        protocol: Protocol::Hysteria2 {
            password: Secret::new(password),
            obfs,
        },
        transport: Transport::Quic,
        security: Security::Tls(TlsSettings {
            sni: q.get("sni").filter(|s| !s.is_empty()).cloned(),
            alpn: vec!["h3".into()],
            fingerprint: None,
            allow_insecure: matches!(q.get("insecure").map(String::as_str), Some("1" | "true")),
        }),
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_salamander() {
        let s = parse("hysteria2://secret@hy.example.com:8443/?sni=hy.example.com&obfs=salamander&obfs-password=x#HY").unwrap();
        let Protocol::Hysteria2 { password, obfs } = &s.protocol else {
            panic!()
        };
        assert_eq!(password.expose(), "secret");
        assert_eq!(obfs.as_ref().map(|o| o.kind.as_str()), Some("salamander"));
        assert_eq!(s.port, 8443);
    }

    #[test]
    fn default_port_and_user_pass_form() {
        let s = parse("hy2://user:pass@hy.example.com/?insecure=1").unwrap();
        let Protocol::Hysteria2 { password, .. } = &s.protocol else {
            panic!()
        };
        assert_eq!(password.expose(), "user:pass");
        assert_eq!(s.port, 443);
    }

    #[test]
    fn port_hopping_reported() {
        assert_eq!(
            parse("hy2://p@h.example.com:443,20000-30000/").unwrap_err(),
            ParseError::Unsupported("Hysteria2 с диапазоном портов")
        );
    }
}
