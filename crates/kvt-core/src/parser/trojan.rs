use super::stream::{parse_security, parse_transport};
use super::{decode_component, host_of, name_of, parse_url, port_of, query_of, ParseError};
use crate::model::{Protocol, Server};
use crate::secret::Secret;

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let url = parse_url(input)?;
    let password = decode_component(url.username());
    if password.is_empty() {
        return Err(ParseError::MissingField("пароль"));
    }
    let address = host_of(&url)?;
    let port = port_of(&url)?;
    let q = query_of(&url);

    Ok(Server {
        name: name_of(&url, &address),
        protocol: Protocol::Trojan {
            password: Secret::new(password),
        },
        transport: parse_transport(&q)?,
        // Trojan по умолчанию работает поверх TLS.
        security: parse_security(&q, "tls")?,
        address,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Security, Transport};

    #[test]
    fn defaults_to_tls_with_host_as_sni() {
        let s = parse("trojan://p%40ss@example.com:443#Tr").unwrap();
        let Protocol::Trojan { password } = &s.protocol else {
            panic!()
        };
        assert_eq!(password.expose(), "p@ss");
        assert!(matches!(s.security, Security::Tls(_)));
        assert_eq!(s.visible_sni(), Some("example.com"));
    }

    #[test]
    fn grpc_transport() {
        let s = parse("trojan://p@example.com:443?type=grpc&serviceName=svc&sni=front.example.com")
            .unwrap();
        assert_eq!(
            s.transport,
            Transport::Grpc {
                service_name: "svc".into()
            }
        );
        assert_eq!(s.visible_sni(), Some("front.example.com"));
    }
}
