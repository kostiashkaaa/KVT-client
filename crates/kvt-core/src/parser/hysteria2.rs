//! Hysteria2: `hysteria2://auth@host:443?sni=…&obfs=salamander&obfs-password=…#имя`.
//! Port hopping — в адресе (`host:443,20000-30000`, как в официальном клиенте) или в
//! параметре `mport=20000-30000` (v2rayN, NekoBox). `pinSHA256` запоминается, но не
//! применяется (см. `Server::warnings`), `ech` — как у остальных протоколов.

use super::{decode_component, host_of, name_of, parse_url, port_of, query_of, ParseError};
use crate::model::{Hysteria2Obfs, Protocol, Security, Server, TlsSettings, Transport};
use crate::secret::Secret;

/// Больше диапазонов портов не принимаем — ссылка явно испорчена.
const MAX_PORT_RANGES: usize = 16;

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let (input, hops_in_address) = split_port_ranges(input)?;
    let url = parse_url(&input)?;
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
        return Err(ParseError::MissingField(crate::i18n::tr(
            "пароль",
            "password",
        )));
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
    let ports = match hops_in_address {
        Some(p) => Some(p),
        None => q
            .get("mport")
            .map(|m| m.trim())
            .filter(|m| !m.is_empty())
            .map(normalize_ranges)
            .transpose()?,
    };

    let pin_sha256 = q
        .get("pinsha256")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(normalize_pin)
        .transpose()?;

    Ok(Server {
        name: name_of(&url, &address),
        port: port_of(&url).or_else(|e| match e {
            ParseError::MissingField(_) => Ok(443),
            other => Err(other),
        })?,
        protocol: Protocol::Hysteria2 {
            password: Secret::new(password),
            obfs,
            ports,
            pin_sha256,
        },
        transport: Transport::Quic,
        security: Security::Tls(TlsSettings {
            sni: q.get("sni").filter(|s| !s.is_empty()).cloned(),
            alpn: vec!["h3".into()],
            fingerprint: None,
            allow_insecure: matches!(q.get("insecure").map(String::as_str), Some("1" | "true")),
            ech: super::stream::parse_ech(&q)?,
        }),
        address,
        fragment: None,
        mux: None,
    })
}

/// Диапазон портов в адресе ломает разбор URL: `host:443,20000-30000` заменяется на
/// `host:443` (первый порт), а диапазоны возвращаются отдельно.
fn split_port_ranges(input: &str) -> Result<(String, Option<String>), ParseError> {
    let Some(scheme_end) = input.find("://").map(|i| i + 3) else {
        return Ok((input.to_owned(), None));
    };
    let rest = &input[scheme_end..];
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_len];
    let host_start = authority.rfind('@').map_or(0, |i| i + 1);
    let host_port = &authority[host_start..];
    // У IPv6 двоеточия внутри скобок — порт только после `]`.
    let port_from = host_port.rfind(']').unwrap_or(0);
    let Some(colon) = host_port[port_from..].rfind(':').map(|i| i + port_from) else {
        return Ok((input.to_owned(), None));
    };
    let spec = &host_port[colon + 1..];
    if !spec.contains([',', '-']) {
        return Ok((input.to_owned(), None));
    }
    let ranges = normalize_ranges(spec)?;
    let first = ranges
        .split([',', '-'])
        .next()
        .unwrap_or_default()
        .to_owned();
    let cut = scheme_end + host_start + colon + 1;
    let rebuilt = format!("{}{first}{}", &input[..cut], &input[cut + spec.len()..]);
    Ok((rebuilt, Some(ranges)))
}

/// `443,20000-30000` или `20000:30000` → `443,20000-30000`. Порты 1–65535, начало
/// диапазона не больше конца.
fn normalize_ranges(spec: &str) -> Result<String, ParseError> {
    let bad = || ParseError::InvalidField {
        field: crate::i18n::tr("порты", "ports"),
        reason: crate::i18n::tr(
            "ожидается список вида 443,20000-30000",
            "expected a list like 443,20000-30000",
        ),
    };
    let parts: Vec<&str> = spec.split(',').map(str::trim).collect();
    if parts.is_empty() || parts.len() > MAX_PORT_RANGES {
        return Err(bad());
    }
    let port = |s: &str| s.trim().parse::<u16>().ok().filter(|p| *p > 0);
    parts
        .into_iter()
        .map(|part| {
            let (a, b) = part
                .split_once('-')
                .or_else(|| part.split_once(':'))
                .unwrap_or((part, part));
            match (port(a), port(b)) {
                (Some(a), Some(b)) if a == b => Ok(a.to_string()),
                (Some(a), Some(b)) if a < b => Ok(format!("{a}-{b}")),
                _ => Err(bad()),
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.join(","))
}

/// `AB:CD:…` или `abcd…` → 64 строчных hex-символа (SHA-256).
fn normalize_pin(pin: &str) -> Result<String, ParseError> {
    let hex: String = pin
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ParseError::InvalidField {
            field: "pinSHA256",
            reason: crate::i18n::tr("не отпечаток SHA-256", "not a SHA-256 fingerprint"),
        });
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_is_kept_and_reported() {
        let pin = "AB:".repeat(31) + "AB";
        let s = parse(&format!(
            "hy2://p@h.example.com:443?insecure=1&pinSHA256={pin}"
        ))
        .unwrap();
        let Protocol::Hysteria2 { pin_sha256, .. } = &s.protocol else {
            panic!("ожидался Hysteria2")
        };
        assert_eq!(pin_sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(s.warnings().len(), 1);
        assert!(s.warnings()[0].contains("не проверяется"));
        // Без insecure сертификат проверяется обычным способом — предупреждение мягче.
        let s = parse(&format!(
            "hy2://p@h.example.com?pinSHA256={}",
            "0".repeat(64)
        ))
        .unwrap();
        assert!(s.warnings()[0].contains("обычным способом"));
        // Без пина предупреждений нет.
        assert!(parse("hy2://p@h.example.com")
            .unwrap()
            .warnings()
            .is_empty());
        for bad in ["xyz", "ab:cd", &"g".repeat(64)] {
            assert!(
                parse(&format!("hy2://p@h.example.com?pinSHA256={bad}")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn ech_config_is_taken_dns_form_is_refused() {
        const ECH: &str = "AEX%2BDQBBpQAgACB%2FqtKXQOgnyY4kyw6jZ3Zt0ZNy1PtoE6OdBMsyqF4tPQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA%3D";
        let s = parse(&format!("hy2://p@h.example.com?ech={ECH}")).unwrap();
        let Security::Tls(tls) = &s.security else {
            panic!("ожидался TLS")
        };
        assert!(tls.ech.as_deref().is_some_and(|e| e.starts_with("AEX+")));
        assert_eq!(
            parse(
                "hy2://p@h.example.com?ech=cloudflare-ech.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query"
            )
            .unwrap_err(),
            ParseError::Unsupported("ECH с запросом конфига через DNS")
        );
        // base64, но не ECHConfigList (длина не сходится).
        assert!(parse("hy2://p@h.example.com?ech=AAAAAAAA").is_err());
    }

    fn ports_of(s: &Server) -> Option<&str> {
        match &s.protocol {
            Protocol::Hysteria2 { ports, .. } => ports.as_deref(),
            _ => panic!("ожидался Hysteria2"),
        }
    }

    #[test]
    fn with_salamander() {
        let s = parse("hysteria2://secret@hy.example.com:8443/?sni=hy.example.com&obfs=salamander&obfs-password=x#HY").unwrap();
        let Protocol::Hysteria2 { password, obfs, .. } = &s.protocol else {
            panic!()
        };
        assert_eq!(password.expose(), "secret");
        assert_eq!(obfs.as_ref().map(|o| o.kind.as_str()), Some("salamander"));
        assert_eq!(s.port, 8443);
        assert_eq!(ports_of(&s), None);
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
    fn port_hopping_in_address() {
        let s = parse("hy2://p@h.example.com:443,20000-30000/?sni=h.example.com#Хоп").unwrap();
        assert_eq!(s.port, 443);
        assert_eq!(ports_of(&s), Some("443,20000-30000"));
        assert_eq!(s.name, "Хоп");

        let s = parse("hysteria2://p@h.example.com:20000-30000?obfs=none").unwrap();
        assert_eq!(s.port, 20000);
        assert_eq!(ports_of(&s), Some("20000-30000"));

        let s = parse("hy2://p@[2001:db8::1]:443,5000-6000/").unwrap();
        assert_eq!(s.address, "2001:db8::1");
        assert_eq!(ports_of(&s), Some("443,5000-6000"));
    }

    #[test]
    fn port_hopping_in_mport() {
        let s = parse("hy2://p@h.example.com:443?mport=20000-30000,40000#m").unwrap();
        assert_eq!(s.port, 443);
        assert_eq!(ports_of(&s), Some("20000-30000,40000"));
    }

    #[test]
    fn bad_port_ranges_are_rejected() {
        for link in [
            "hy2://p@h.example.com:30000-20000/",
            "hy2://p@h.example.com:0-10/",
            "hy2://p@h.example.com:443,70000-80000/",
            "hy2://p@h.example.com:443?mport=abc",
            "hy2://p@h.example.com:1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17/",
        ] {
            assert!(parse(link).is_err(), "{link}");
        }
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for link in [
            "hy2://",
            "hy2://@:",
            "hy2://p@:-,",
            "hy2://p@h:,",
            "hy2://p@[::1:-1",
            "hy2://p@h:1-",
        ] {
            let _ = parse(link);
        }
    }
}
