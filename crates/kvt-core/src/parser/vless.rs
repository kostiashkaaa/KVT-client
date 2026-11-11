use super::stream::{parse_security, parse_transport, parse_tuning};
use super::{decode_component, host_of, name_of, parse_url, port_of, query_of, ParseError};
use crate::model::{Protocol, Server, VlessFlow};
use crate::secret::Secret;

pub(super) fn parse(input: &str) -> Result<Server, ParseError> {
    let url = parse_url(input)?;
    let id = decode_component(url.username());
    validate_id(&id)?;
    let address = host_of(&url)?;
    let port = port_of(&url)?;
    let q = query_of(&url);

    let flow = match q.get("flow").map(|s| s.trim()) {
        None | Some("") => None,
        Some("xtls-rprx-vision") => Some(VlessFlow::XtlsRprxVision),
        Some(_) => return Err(ParseError::Unsupported("flow")),
    };
    let encryption = q
        .get("encryption")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s != "none");

    let (fragment, mux) = parse_tuning(&q)?;
    Ok(Server {
        name: name_of(&url, &address),
        protocol: Protocol::Vless {
            id: Secret::new(id),
            flow,
            encryption,
        },
        transport: parse_transport(&q)?,
        security: parse_security(&q, "none")?,
        address,
        port,
        fragment,
        mux,
    })
}

/// UUID, либо произвольная строка до 30 байт (Xray превращает её в UUID сам).
fn validate_id(id: &str) -> Result<(), ParseError> {
    if id.is_empty() {
        return Err(ParseError::MissingField("id"));
    }
    if uuid::Uuid::parse_str(id).is_ok() || id.len() <= 30 {
        Ok(())
    } else {
        Err(ParseError::InvalidField {
            field: "id",
            reason: crate::i18n::tr("не UUID", "not a UUID"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Fingerprint, Security, Transport};

    #[test]
    fn reality_vision() {
        let s = parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443?security=reality&sni=www.microsoft.com&fp=edge&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba8&flow=xtls-rprx-vision#NL").unwrap();
        assert_eq!(s.address, "2001:db8::1");
        assert_eq!(s.name, "NL");
        assert_eq!(s.transport, Transport::Tcp);
        let Security::Reality(r) = &s.security else {
            panic!("ожидался reality")
        };
        assert_eq!(r.fingerprint, Fingerprint::Edge);
        assert_eq!(s.visible_sni(), Some("www.microsoft.com"));
    }

    #[test]
    fn xhttp_tls() {
        let s = parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?type=xhttp&security=tls&sni=cdn.example.com&path=%2Fapi&mode=auto&alpn=h2,http/1.1").unwrap();
        assert_eq!(
            s.transport,
            Transport::Xhttp {
                path: "/api".into(),
                host: None,
                mode: Some("auto".into()),
                extra: None,
            }
        );
        let Security::Tls(tls) = &s.security else {
            panic!("ожидался tls")
        };
        assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn xhttp_extra_fragment_and_mux() {
        let extra = r#"{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"},"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","publicKey":"k","shortId":"ab","fingerprint":"firefox"},"sockopt":{"interface":"x"}}}"#;
        let link = format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@up.example.com:443?type=xhttp&security=tls&path=%2Fx&extra={}&fragment=tlshello,100-200,10-20&mux=8",
            percent_encoding::utf8_percent_encode(extra, percent_encoding::NON_ALPHANUMERIC)
        );
        let s = parse(&link).unwrap();
        let Transport::Xhttp {
            extra: Some(extra), ..
        } = &s.transport
        else {
            panic!("ожидался XHTTP с extra")
        };
        assert!(extra.contains("xPaddingBytes") && !extra.contains("sockopt"));
        assert_eq!(
            s.endpoints(),
            ["up.example.com".to_owned(), "dl.example.com".to_owned()]
        );
        let f = s.fragment.as_ref().unwrap();
        assert_eq!(
            (f.packets.as_str(), f.length.as_str()),
            ("tlshello", "100-200")
        );
        assert_eq!(s.mux, Some(8));
    }

    #[test]
    fn bad_tuning_is_an_error() {
        let base = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?security=tls";
        for bad in [
            "&fragment=tlshello,0-10,5",
            "&fragment=tlshello,100",
            "&fragment=99,100,5",
            "&fragment=tlshello,100,5000",
            "&mux=0",
            "&mux=abc",
            "&type=xhttp&extra=%7Bnot",
        ] {
            assert!(parse(&format!("{base}{bad}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn reality_requires_valid_key() {
        let err = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?security=reality&sni=a.com&pbk=abc",
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::InvalidField { field: "pbk", .. }));
    }

    #[test]
    fn missing_port_is_error() {
        assert_eq!(
            parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@h").unwrap_err(),
            ParseError::MissingField("порт")
        );
    }
}
