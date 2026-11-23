//! Выбор ядра для сервера. Оба ядра поднимают собственный TUN, поэтому цепочек
//! через локальный SOCKS (и открытых портов на 127.0.0.1) нет.

use crate::model::{Protocol, Server, Transport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoreKind {
    Xray,
    SingBox,
    /// sing-box со сборкой AmneziaWG (`sing-box-awg.exe`): запускается только для
    /// серверов AmneziaWG, у остальных — штатный `SingBox` (в форке подменены
    /// сетевые библиотеки, чужим серверам они не нужны).
    SingBoxAwg,
}

impl CoreKind {
    /// Конфиг в формате sing-box: `SingBox` и `SingBoxAwg` читают один и тот же.
    pub fn is_sing_box(self) -> bool {
        matches!(self, Self::SingBox | Self::SingBoxAwg)
    }
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
    if let Protocol::WireGuard(wg) = &server.protocol {
        // Xray умеет WireGuard, но без обфускации и без нашего TUN-пути: берём sing-box.
        return if wg.awg.is_some() {
            CoreChoice {
                core: CoreKind::SingBoxAwg,
                required_by: Some("AmneziaWG"),
            }
        } else {
            CoreChoice {
                core: CoreKind::SingBox,
                required_by: None,
            }
        };
    }
    let core = match server.protocol {
        // REALITY и Vision — родная территория Xray.
        Protocol::Vless { .. } | Protocol::Trojan { .. } | Protocol::Vmess { .. } => CoreKind::Xray,
        Protocol::Hysteria2 { .. }
        | Protocol::Shadowsocks { .. }
        | Protocol::Tuic { .. }
        | Protocol::AnyTls { .. }
        | Protocol::Socks { .. }
        | Protocol::Http { .. } => CoreKind::SingBox,
        Protocol::WireGuard(_) => CoreKind::SingBox,
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
