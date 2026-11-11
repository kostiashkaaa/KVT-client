//! AnyTLS: `anytls://password@host:port?sni=…&insecure=1#имя`. Всегда поверх TLS,
//! только через sing-box.

use super::stream::parse_security;
use super::{decode_component, host_of, name_of, parse_url, port_of, query_of, ParseError};
use crate::model::{Protocol, Security, Server, Transport};
use crate::secret::Secret;

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let url = parse_url(input)?;
    let password = decode_component(url.username());
    if password.is_empty() {
        return Err(ParseError::MissingField(crate::i18n::tr(
            "пароль",
            "password",
        )));
    }
    let address = host_of(&url)?;
    let port = port_of(&url)?;
    let q = query_of(&url);
    let security = parse_security(&q, "tls")?;
    if !matches!(security, Security::Tls(_)) {
        return Err(ParseError::Unsupported(crate::i18n::tr(
            "AnyTLS без TLS",
            "AnyTLS without TLS",
        )));
    }
    Ok(Server {
        name: name_of(&url, &address),
        protocol: Protocol::AnyTls {
            password: Secret::new(password),
        },
        transport: Transport::Tcp,
        security,
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
        let s =
            parse("anytls://secret@a.example.com:443?sni=a.example.com&fp=firefox#AnyTLS").unwrap();
        assert_eq!(s.name, "AnyTLS");
        assert!(
            matches!(&s.security, Security::Tls(t) if t.sni.as_deref() == Some("a.example.com"))
        );
        assert!(
            matches!(&s.protocol, Protocol::AnyTls { password } if password.expose() == "secret")
        );
    }

    #[test]
    fn needs_password_and_tls() {
        assert!(parse("anytls://@a.example.com:443").is_err());
        assert!(parse("anytls://p@a.example.com:443?security=reality").is_err());
    }
}
