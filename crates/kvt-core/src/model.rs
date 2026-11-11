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
    /// Фрагментация первых пакетов к серверу — от провайдера (`fragment=` в ссылке,
    /// `finalmask` или `dialerProxy` во фрагментирующий `freedom` в JSON Xray).
    /// Провайдер ставит её, когда без неё ТСПУ режет рукопожатие.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<Fragment>,
    /// Mux провайдера (`mux=` в ссылке, `mux` в JSON Xray): сколько потоков в одном
    /// соединении с сервером. Только Xray и не с Vision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<u16>,
}

/// Фрагментация: куски длиной `length` байт с паузами `delay` мс. Диапазоны —
/// `число` или `от-до`, проверены при разборе.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment {
    /// `tlshello` — только ClientHello, или номера первых пакетов `1-3`.
    pub packets: String,
    pub length: String,
    pub delay: String,
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
        /// Port hopping: диапазоны портов `20000-30000,40000`; `port` сервера — первый
        /// из них (или порт из ссылки при `mport=`). Без диапазона поле не пишется —
        /// ключи серверов и дубликаты считаются как раньше.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ports: Option<String>,
        /// `pinSHA256` из ссылки — отпечаток сертификата сервера (hex). sing-box
        /// сверять сертификат по отпечатку не умеет (только по ключу), поэтому пин
        /// не применяется — об этом говорит `Server::warnings`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin_sha256: Option<String>,
    },
    /// VMess (только AEAD, `alterId` = 0). `cipher` — `auto`, `aes-128-gcm`,
    /// `chacha20-poly1305`, `none` или `zero`.
    Vmess {
        id: Secret,
        cipher: String,
    },
    /// TUIC v5 поверх QUIC — только sing-box.
    Tuic {
        uuid: Secret,
        password: Secret,
        congestion: Option<String>,
        udp_relay_mode: Option<String>,
    },
    /// AnyTLS — только sing-box.
    AnyTls {
        password: Secret,
    },
    /// Обычный прокси SOCKS5 (без шифрования) — через sing-box.
    Socks {
        username: Option<Secret>,
        password: Option<Secret>,
    },
    /// HTTP-прокси (CONNECT), у `https://` — поверх TLS. Только sing-box.
    Http {
        username: Option<Secret>,
        password: Option<Secret>,
    },
}

impl Protocol {
    pub fn kind(&self) -> &'static str {
        match self {
            Protocol::Vless { .. } => "vless",
            Protocol::Trojan { .. } => "trojan",
            Protocol::Shadowsocks { .. } => "shadowsocks",
            Protocol::Hysteria2 { .. } => "hysteria2",
            Protocol::Vmess { .. } => "vmess",
            Protocol::Tuic { .. } => "tuic",
            Protocol::AnyTls { .. } => "anytls",
            Protocol::Socks { .. } => "socks",
            Protocol::Http { .. } => "http",
        }
    }

    /// Работает поверх QUIC (UDP): TCP-пинг к такому серверу ничего не говорит.
    pub fn is_quic(&self) -> bool {
        matches!(self, Protocol::Hysteria2 { .. } | Protocol::Tuic { .. })
    }
}

impl Server {
    /// Адреса, с которыми соединяется ядро: сервер и, у XHTTP с раздельной загрузкой,
    /// сервер загрузки. Все они — мимо zapret и скрываются в журналах.
    pub fn endpoints(&self) -> Vec<String> {
        let mut out = vec![self.address.clone()];
        if let Some(download) = self.download_address() {
            if download != self.address {
                out.push(download);
            }
        }
        out
    }

    /// Адрес сервера загрузки XHTTP (`downloadSettings.address` в `extra`).
    pub fn download_address(&self) -> Option<String> {
        let Transport::Xhttp {
            extra: Some(extra), ..
        } = &self.transport
        else {
            return None;
        };
        let v: serde_json::Value = serde_json::from_str(extra).ok()?;
        v["downloadSettings"]["address"].as_str().map(str::to_owned)
    }

    /// Что из ссылки сервера KVT не применяет — говорится при добавлении, а не
    /// отбрасывается молча. Тексты без секретов: они уходят в окно.
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let sing_box =
            crate::core_select::select_core(self).core == crate::core_select::CoreKind::SingBox;
        if sing_box && self.fragment.is_some() && !crate::compile::sing_box_fragments(self) {
            out.push(crate::i18n::tr(
                "фрагментация от провайдера не применяется — ядро sing-box делает её только для TLS",
                "the provider's fragmentation isn't applied — the sing-box core only does it for TLS",
            ));
        }
        if self.mux.is_some() && !crate::compile::mux_applies(self) {
            out.push(crate::i18n::tr(
                "mux от провайдера не применяется — он работает только в ядре Xray и не с Vision или XHTTP",
                "the provider's mux isn't applied — it only works in the Xray core and not with Vision or XHTTP",
            ));
        }
        if let Protocol::Hysteria2 {
            pin_sha256: Some(_),
            ..
        } = &self.protocol
        {
            let insecure = matches!(&self.security, Security::Tls(t) if t.allow_insecure);
            out.push(if insecure {
                crate::i18n::tr("сертификат сервера не проверяется — VPN-ядро не умеет сверять отпечаток pinSHA256", "the server certificate isn't verified — the VPN core can't check the pinSHA256 fingerprint")
            } else {
                crate::i18n::tr("отпечаток pinSHA256 не сверяется — сертификат проверяется обычным способом", "the pinSHA256 fingerprint isn't checked — the certificate is verified the usual way")
            });
        }
        out
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
        /// Остальные настройки XHTTP (`extra` ссылки): xmux, паддинг, заголовки,
        /// `downloadSettings`. JSON после белого списка (`parser::xhttp_extra`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
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
    /// Encrypted Client Hello: готовый ECHConfigList в base64 (параметр `ech`
    /// ссылки). Имя сервера в рукопожатии тогда скрыто от провайдера.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech: Option<String>,
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
