//! Выбор ядра для сервера. Оба ядра поднимают собственный TUN, поэтому цепочек
//! через локальный SOCKS (и открытых портов на 127.0.0.1) нет.

use crate::model::{Protocol, Server, Transport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoreKind {
    Xray,
    SingBox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreChoice {
    pub core: CoreKind,
    /// Возможность, которую умеет только это ядро; `None` — выбор по предпочтению.
    pub required_by: Option<&'static str>,
}

pub fn select_core(server: &Server) -> CoreChoice {
    if let Transport::Xhttp { .. } = server.transport {
        return CoreChoice {
            core: CoreKind::Xray,
            required_by: Some("XHTTP"),
        };
    }
    if let Protocol::Vless {
        encryption: Some(_),
        ..
    } = server.protocol
    {
        return CoreChoice {
            core: CoreKind::Xray,
            required_by: Some("VLESS Encryption"),
        };
    }
    let core = match server.protocol {
        // REALITY и Vision — родная территория Xray.
        Protocol::Vless { .. } | Protocol::Trojan { .. } | Protocol::Vmess { .. } => CoreKind::Xray,
        Protocol::Hysteria2 { .. }
        | Protocol::Shadowsocks { .. }
        | Protocol::Tuic { .. }
        | Protocol::AnyTls { .. }
        | Protocol::Socks { .. } => CoreKind::SingBox,
    };
    CoreChoice {
        core,
        required_by: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_uri, Entry};

    fn server(uri: &str) -> Server {
        match parse_uri(uri).unwrap() {
            Entry::Server(s) => *s,
            Entry::Info(_) => panic!("ожидался сервер"),
        }
    }

    #[test]
    fn xhttp_requires_xray() {
        let s = server(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example:443?type=xhttp&security=tls",
        );
        assert_eq!(
            select_core(&s),
            CoreChoice {
                core: CoreKind::Xray,
                required_by: Some("XHTTP")
            }
        );
    }

    #[test]
    fn hysteria2_prefers_sing_box() {
        let s = server("hy2://p@h.example:443");
        assert_eq!(select_core(&s).core, CoreKind::SingBox);
    }
}
