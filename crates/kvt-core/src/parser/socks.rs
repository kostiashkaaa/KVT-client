//! SOCKS5: `socks5://user:pass@host:1080#имя` или как у v2rayN —
//! `socks://base64(user:pass)@host:1080#имя`. Трафик до такого прокси не шифруется;
//! подключение — через sing-box.

use super::{
    decode_base64_lenient, decode_component, host_of, name_of, parse_url, port_of, ParseError,
};
use crate::model::{Protocol, Security, Server, Transport};
use crate::secret::Secret;

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let scheme = input
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default();
    if scheme == "socks4" || scheme == "socks4a" {
        return Err(ParseError::Unsupported("SOCKS4"));
    }
    let url = parse_url(input)?;
    let user = decode_component(url.username());
    let (username, password) = match url.password() {
        Some(p) => (user, decode_component(p)),
        // v2rayN кладёт `user:pass` в base64 целиком.
        None => match decode_base64_lenient(&user)
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())))
        {
            Some(pair) => pair,
            None => (user, String::new()),
        },
    };
    let address = host_of(&url)?;
    let port = port_of(&url)?;
    let secret = |s: String| Some(s).filter(|s| !s.is_empty()).map(Secret::new);
    Ok(Server {
        name: name_of(&url, &address),
        protocol: Protocol::Socks {
            username: secret(username),
            password: secret(password),
        },
        transport: Transport::Tcp,
        security: Security::None,
        address,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(s: &Server) -> (Option<&str>, Option<&str>) {
        match &s.protocol {
            Protocol::Socks { username, password } => (
                username.as_ref().map(Secret::expose),
                password.as_ref().map(Secret::expose),
            ),
            _ => panic!("ожидался SOCKS"),
        }
    }

    #[test]
    fn plain_user_and_password() {
        let s = parse("socks5://us%40er:p%3Ass@proxy.example.com:1080#Прокси").unwrap();
        assert_eq!(creds(&s), (Some("us@er"), Some("p:ss")));
        assert_eq!((s.address.as_str(), s.port), ("proxy.example.com", 1080));
        assert_eq!(s.name, "Прокси");
    }

    #[test]
    fn v2rayn_base64_userinfo() {
        // base64("user:pass")
        let s = parse("socks://dXNlcjpwYXNz@1.2.3.4:1080#s").unwrap();
        assert_eq!(creds(&s), (Some("user"), Some("pass")));
    }

    #[test]
    fn without_auth() {
        let s = parse("socks://proxy.example.com:1080").unwrap();
        assert_eq!(creds(&s), (None, None));
        assert_eq!(s.name, "proxy.example.com");
    }

    #[test]
    fn bad_links_are_rejected() {
        assert!(parse("socks5://proxy.example.com").is_err());
        assert!(parse("socks5://u:p@:1080").is_err());
        assert_eq!(
            parse("socks4://proxy.example.com:1080").unwrap_err(),
            ParseError::Unsupported("SOCKS4")
        );
    }
}
