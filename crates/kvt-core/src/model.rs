//! Внутренняя модель сервера. Любой входной формат (URI, JSON Xray/sing-box,
//! Clash YAML) приводится к ней, а конфиги ядер генерируются только из неё.

use crate::secret::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// Имя из ссылки (`#fragment`). Данные провайдера — выводятся только как текст.
    pub name: String,
    pub address: String,
    pub port: u16,
    pub protocol: Protocol,
    pub transport: Transport,
    pub security: Security,
}

impl Server {
    /// SNI, который увидит ТСПУ. По нему сетевой диспетчер считает лимиты
    /// новых TLS-соединений.
    pub fn visible_sni(&self) -> Option<&str> {
        match &self.security {
            Security::None => None,
            Security::Tls(tls) => Some(tls.sni.as_deref().unwrap_or(&self.address)),
            Security::Reality(r) => Some(&r.sni),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Protocol {
    Vless {
        id: Secret,
        flow: Option<VlessFlow>,
        /// VLESS Encryption (ML-KEM-768) — только Xray. `None` = "none".
        encryption: Option<String>,
    },
    Trojan {
        password: Secret,
    },
    Shadowsocks {
        method: String,
        password: Secret,
    },
    Hysteria2 {
        password: Secret,
        obfs: Option<Hysteria2Obfs>,
    },
}

impl Protocol {
    pub fn kind(&self) -> &'static str {
        match self {
            Protocol::Vless { .. } => "vless",
            Protocol::Trojan { .. } => "trojan",
            Protocol::Shadowsocks { .. } => "shadowsocks",
            Protocol::Hysteria2 { .. } => "hysteria2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VlessFlow {
    XtlsRprxVision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2Obfs {
    /// Сейчас поддерживается только `salamander`.
    pub kind: String,
    pub password: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Ws {
        path: String,
        host: Option<String>,
    },
    Grpc {
        service_name: String,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    /// XHTTP (бывший SplitHTTP) — только Xray.
    Xhttp {
        path: String,
        host: Option<String>,
        mode: Option<String>,
    },
    /// Hysteria2 и другие протоколы поверх QUIC, у которых нет отдельного транспорта.
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Security {
    None,
    Tls(TlsSettings),
    Reality(RealitySettings),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSettings {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub fingerprint: Option<Fingerprint>,
    /// Отключённая проверка сертификата. Показывается в UI как предупреждение.
    pub allow_insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealitySettings {
    pub sni: String,
    pub public_key: String,
    pub short_id: String,
    pub fingerprint: Fingerprint,
    pub spider_x: Option<String>,
}

/// Пресеты uTLS. `Randomized` строит отпечаток, которого нет ни у одного
/// браузера, — советник предупреждает о нём.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fingerprint {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Ios,
    Android,
    /// Браузеры QQ и 360 — китайские сборки Chromium; их отпечатки есть и в Xray, и в
    /// sing-box, провайдеры иногда выбирают их нарочно.
    Qq,
    #[serde(rename = "360")]
    Browser360,
    Random,
    Randomized,
}

impl Fingerprint {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "chrome" => Self::Chrome,
            "firefox" => Self::Firefox,
            "edge" => Self::Edge,
            "safari" => Self::Safari,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "qq" => Self::Qq,
            "360" => Self::Browser360,
            "random" => Self::Random,
            "randomized" => Self::Randomized,
            _ => return None,
        })
    }

    /// Совет по отпечатку на основе наблюдений сообщества (2026): Chrome/Safari/iOS
    /// чаще попадают под подозрение, синтетический `randomized` выделяется.
    pub fn advice(self) -> FingerprintAdvice {
        match self {
            Self::Firefox | Self::Edge | Self::Android => FingerprintAdvice::Ok,
            Self::Randomized => FingerprintAdvice::Avoid,
            Self::Chrome
            | Self::Safari
            | Self::Ios
            | Self::Qq
            | Self::Browser360
            | Self::Random => FingerprintAdvice::Suspicious,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintAdvice {
    Ok,
    Suspicious,
    Avoid,
}
