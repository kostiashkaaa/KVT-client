//! HTTP-прокси: `http://user:pass@host:8080#имя` или поверх TLS —
//! `https://user:pass@host:443?sni=…&insecure=1#имя`. Подключение — через sing-box.
//!
//! `https://…` — это и адрес подписки, и ссылка на сайт в теле подписки («наш
//! канал: https://t.me/…»). Прокси от них отличает логин в адресе и пустой путь:
//! у подписки всегда есть путь с токеном, у прокси без логина KVT не берёт.

use super::stream::parse_security;
use super::{decode_component, host_of, name_of, parse_url, query_of, ParseError};
use crate::model::{Protocol, Security, Server, Transport};
use crate::secret::Secret;
use url::Url;

/// Ссылка `http(s)://` — на прокси, а не на сайт или подписку.
pub fn is_proxy_link(input: &str) -> bool {
    Url::parse(input.trim()).is_ok_and(|url| is_proxy_url(&url))
}

fn is_proxy_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && !url.username().is_empty()
        && matches!(url.path(), "" | "/")
}

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let url = parse_url(input)?;
    if !is_proxy_url(&url) {
        // Не прокси — как и раньше, «неизвестная схема»: в теле подписки это
        // ссылка на сайт, она просто пропускается.
        return Err(ParseError::UnknownScheme(url.scheme().to_owned()));
    }
    let username = decode_component(url.username());
    let password = url.password().map(decode_component).unwrap_or_default();
    let address = host_of(&url)?;
    let port = match url.port_or_known_default() {
        Some(0) | None => return Err(ParseError::MissingField(crate::i18n::tr("порт", "port"))),
        Some(p) => p,
    };
    let q = query_of(&url);
    let security = if url.scheme() == "https" {
        match parse_security(&q, "tls")? {
            tls @ Security::Tls(_) => tls,
            _ => {
                return Err(ParseError::Unsupported(crate::i18n::tr(
                    "HTTPS-прокси без TLS",
                    "HTTPS proxy without TLS",
                )))
            }
        }
    } else {
        Security::None
    };
    let secret = |s: String| Some(s).filter(|s| !s.is_empty()).map(Secret::new);
    Ok(Server {
        name: name_of(&url, &address),
        protocol: Protocol::Http {
            username: secret(username),
            password: secret(password),
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

    fn creds(s: &Server) -> (Option<&str>, Option<&str>) {
        match &s.protocol {
            Protocol::Http { username, password } => (
                username.as_ref().map(Secret::expose),
                password.as_ref().map(Secret::expose),
            ),
            _ => panic!("ожидался HTTP-прокси"),
        }
    }

    #[test]
    fn plain_http_proxy() {
        let s = parse("http://us%40er:p%3Ass@proxy.example.com:8080#Прокси").unwrap();
        assert_eq!(creds(&s), (Some("us@er"), Some("p:ss")));
        assert_eq!((s.address.as_str(), s.port), ("proxy.example.com", 8080));
        assert_eq!(s.security, Security::None);
        assert_eq!(s.name, "Прокси");
    }

    #[test]
    fn https_proxy_uses_tls_and_default_port() {
        let s = parse("https://u:p@proxy.example.com/?sni=front.example.com&insecure=1").unwrap();
        assert_eq!(s.port, 443);
        let Security::Tls(tls) = &s.security else {
            panic!("ожидался TLS")
        };
        assert_eq!(tls.sni.as_deref(), Some("front.example.com"));
        assert!(tls.allow_insecure);
        assert!(parse("https://u:p@proxy.example.com:8443?security=none").is_err());
    }

    #[test]
    fn sites_and_subscriptions_are_not_proxies() {
        for link in [
            "https://t.me/channel",
            "https://sub.example.com/abc123",
            "https://sub.example.com:8443/",
            "http://proxy.example.com:8080",
            "https://u:p@sub.example.com/sub/token",
        ] {
            assert!(!is_proxy_link(link), "{link}");
            assert!(
                matches!(parse(link), Err(ParseError::UnknownScheme(_))),
                "{link}"
            );
        }
        assert!(is_proxy_link("http://u@proxy.example.com:3128"));
        assert!(!is_proxy_link("socks5://u:p@proxy.example.com:1080"));
        assert!(!is_proxy_link("не ссылка"));
    }

    #[test]
    fn broken_links_are_rejected() {
        assert!(parse("http://u:p@:8080").is_err());
        assert!(parse("http://u:p@proxy.example.com:0").is_err());
        assert!(parse("https://u:p@proxy.example.com?fp=нечто").is_err());
    }
}
