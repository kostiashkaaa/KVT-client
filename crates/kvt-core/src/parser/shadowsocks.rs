//! `ss://` в форматах SIP002 (`base64(method:password)@host:port`,
//! `method:password@host:port` для 2022-*) и устаревшем `base64(method:password@host:port)`.

use super::{
    decode_base64_lenient, decode_component, host_of, name_of, parse_url, port_of, ParseError,
};
use crate::model::{Protocol, Security, Server, Transport};
use crate::secret::Secret;

const SUPPORTED_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
];

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let input = normalize_legacy(input)?;
    let url = parse_url(&input)?;

    let (method, password) = match url.password() {
        Some(pass) => (decode_component(url.username()), decode_component(pass)),
        None => {
            let raw = decode_component(url.username());
            let bytes = decode_base64_lenient(&raw).ok_or(ParseError::InvalidField {
                field: "userinfo",
                reason: crate::i18n::tr("ожидается base64", "expected base64"),
            })?;
            let text = String::from_utf8(bytes).map_err(|_| ParseError::InvalidUrl)?;
            let (m, p) = text
                .split_once(':')
                .ok_or(ParseError::MissingField(crate::i18n::tr(
                    "пароль",
                    "password",
                )))?;
            (m.to_owned(), p.to_owned())
        }
    };

    let method = method.to_ascii_lowercase();
    if !SUPPORTED_METHODS.contains(&method.as_str()) {
        return Err(ParseError::Unsupported(crate::i18n::tr(
            "метод шифрования Shadowsocks",
            "Shadowsocks cipher",
        )));
    }
    if password.is_empty() {
        return Err(ParseError::MissingField(crate::i18n::tr(
            "пароль",
            "password",
        )));
    }
    if url.query_pairs().any(|(k, _)| k == "plugin") {
        return Err(ParseError::Unsupported(crate::i18n::tr(
            "плагины Shadowsocks",
            "Shadowsocks plugins",
        )));
    }

    let address = host_of(&url)?;
    Ok(Server {
        name: name_of(&url, &address),
        port: port_of(&url)?,
        protocol: Protocol::Shadowsocks {
            method,
            password: Secret::new(password),
        },
        transport: Transport::Tcp,
        security: Security::None,
        address,
    })
}

/// `ss://BASE64#name` → `ss://method:password@host:port#name`.
fn normalize_legacy(input: &str) -> Result<String, ParseError> {
    let rest = &input["ss://".len()..];
    let (body, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (rest, None),
    };
    if body.contains('@') {
        return Ok(input.to_owned());
    }
    let bytes = decode_base64_lenient(body).ok_or(ParseError::InvalidUrl)?;
    let decoded = String::from_utf8(bytes).map_err(|_| ParseError::InvalidUrl)?;
    let (userinfo, hostport) = decoded.rsplit_once('@').ok_or(ParseError::InvalidUrl)?;
    let (method, password) =
        userinfo
            .split_once(':')
            .ok_or(ParseError::MissingField(crate::i18n::tr(
                "пароль",
                "password",
            )))?;
    let enc = |s: &str| {
        percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
    };
    let mut out = format!("ss://{}:{}@{}", enc(method), enc(password), hostport);
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;

    fn creds(s: &Server) -> (&str, &str) {
        let Protocol::Shadowsocks { method, password } = &s.protocol else {
            panic!()
        };
        (method, password.expose())
    }

    #[test]
    fn sip002_base64_userinfo() {
        let ui = URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let s = parse(&format!("ss://{ui}@198.51.100.7:8388#SS")).unwrap();
        assert_eq!(creds(&s), ("aes-256-gcm", "secret"));
        assert_eq!(s.port, 8388);
    }

    #[test]
    fn sip002_plain_2022() {
        let s = parse("ss://2022-blake3-aes-128-gcm:a2V5%3D@h.example:443#x").unwrap();
        assert_eq!(creds(&s), ("2022-blake3-aes-128-gcm", "a2V5="));
    }

    #[test]
    fn legacy_whole_base64() {
        let body = STANDARD.encode("chacha20-ietf-poly1305:p@ss:w@1.2.3.4:443");
        let s = parse(&format!("ss://{body}#Old")).unwrap();
        assert_eq!(creds(&s), ("chacha20-ietf-poly1305", "p@ss:w"));
        assert_eq!(s.address, "1.2.3.4");
        assert_eq!(s.name, "Old");
    }

    #[test]
    fn weak_method_rejected() {
        let ui = STANDARD.encode("rc4-md5:x");
        assert!(matches!(
            parse(&format!("ss://{ui}@h:1#")),
            Err(ParseError::Unsupported(_))
        ));
    }
}
