//! Компиляция модели в конфиги ядер. Конфиг всегда строится с нуля из
//! проверенной модели: никаких кусков конфига от провайдера (только поля из белого
//! списка, проверенные парсером), путей от пользователя, API ядра и локальных
//! прокси-портов — единственный inbound это TUN.

mod sing_box;
mod xray;

use crate::core_select::CoreKind;
use crate::lists::RuleSetRef;
use crate::model::{Fingerprint, Protocol, Security, Server, TlsSettings, Transport, VlessFlow};
use crate::routing::{Action, Matcher, RoutingPlan};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use sing_box::compile as compile_sing_box;
pub use xray::compile as compile_xray;

pub const TUN_INTERFACE: &str = "KVT";
pub const TAG_PROXY: &str = "proxy";
pub const TAG_DIRECT: &str = "direct";
pub const TAG_BLOCK: &str = "block";
pub const TAG_TUN: &str = "tun-in";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPlan {
    /// DoH-резолвер для доменов, которые идут через VPN (запросы уходят в туннель).
    pub remote_doh: String,
    /// Резолвер для прямых доменов: российские CDN отдают ближайшие узлы.
    pub local: String,
    /// Запасной DoH через туннель (другой провайдер), если основной не отвечает.
    /// Только у Xray: у sing-box нет перехода на запасной DNS-сервер. Системный
    /// DNS запасным не бывает — его запросы видел бы провайдер интернета.
    #[serde(default)]
    pub reserve_doh: Option<String>,
}

impl Default for DnsPlan {
    fn default() -> Self {
        Self {
            remote_doh: "1.1.1.1".into(),
            local: "77.88.8.8".into(),
            reserve_doh: Some("8.8.8.8".into()),
        }
    }
}

impl DnsPlan {
    /// План из выбора пользователя: id резолверов из [`crate::dns::RESOLVERS`].
    pub fn from_ids(local: &str, remote: &str) -> Result<Self, CompileError> {
        let local = crate::dns::resolver(local).ok_or(CompileError::Dns(local.to_owned()))?;
        let remote = crate::dns::resolver(remote)
            .filter(|r| r.tunnel)
            .and_then(|r| r.doh)
            .ok_or(CompileError::Dns(remote.to_owned()))?;
        // Запасной — первый другой резолвер из каталога, который работает через туннель.
        let reserve = crate::dns::RESOLVERS
            .iter()
            .filter(|r| r.tunnel)
            .filter_map(|r| r.doh)
            .find(|d| d.ip != remote.ip)
            .map(|d| d.ip.to_string());
        Ok(Self {
            remote_doh: remote.ip.to_string(),
            local: local.udp.to_string(),
            reserve_doh: reserve,
        })
    }

    /// Адреса попадают в конфиг ядра, поэтому принимаются только из каталога KVT.
    pub fn validate(&self) -> Result<(), CompileError> {
        let catalog = crate::dns::RESOLVERS;
        if !catalog.iter().any(|r| r.udp.to_string() == self.local) {
            return Err(CompileError::Dns(self.local.clone()));
        }
        let tunnel_doh = |ip: &str| {
            catalog
                .iter()
                .any(|r| r.tunnel && r.doh.is_some_and(|d| d.ip.to_string() == ip))
        };
        if !tunnel_doh(&self.remote_doh) {
            return Err(CompileError::Dns(self.remote_doh.clone()));
        }
        if let Some(reserve) = self.reserve_doh.as_deref().filter(|r| !tunnel_doh(r)) {
            return Err(CompileError::Dns(reserve.to_owned()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileInput<'a> {
    pub server: &'a Server,
    pub routing: &'a RoutingPlan,
    pub dns: &'a DnsPlan,
    /// Каталог с наборами правил. Задаёт служба (ProgramData\KVT\rules), а не пользователь.
    pub rule_set_dir: &'a str,
    /// IPv6 включён в Windows. Если нет, у адаптера TUN нет IPv6-интерфейса, и ядро
    /// не может задать ему IPv6-адрес и маршрут `::/0`: Xray и sing-box падают при
    /// старте с «Element not found». См. [`ipv6_enabled`].
    pub ipv6: bool,
}

/// Адреса адаптера TUN: IPv4 всегда, IPv6 — если он включён в системе.
fn tun_addresses(ipv6: bool) -> Vec<&'static str> {
    let mut out = vec!["172.19.0.1/30"];
    if ipv6 {
        out.push("fdfe:dcba:9876::1/126");
    }
    out
}

/// Включён ли IPv6 на обычных (не туннельных) адаптерах — к ним относится и Wintun.
/// `disabled_components` — значение `DisabledComponents` из
/// `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters` (`None` — значения нет).
/// Бит 0x10 отключает IPv6 на всех адаптерах, кроме loopback и туннельных; так его
/// выключают «оптимизаторы» и инструкции «отключите IPv6» (обычно значение 0xFF).
#[must_use]
pub fn ipv6_enabled(disabled_components: Option<u32>) -> bool {
    disabled_components.map_or(true, |v| v & 0x10 == 0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Compiled {
    pub core: CoreKind,
    pub config: Value,
    /// Что пришлось пропустить (например, правило, которое ядро не умеет).
    pub warnings: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompileError {
    #[error("{}", crate::trf!("{:?} не поддерживает {}", "{:?} doesn't support {}", .core, .feature))]
    Unsupported {
        core: CoreKind,
        feature: &'static str,
    },
    #[error(transparent)]
    Routing(#[from] crate::routing::RoutingError),
    #[error("{}", crate::trf!("DNS-сервер «{}» не из списка KVT", "DNS server “{}” isn't in KVT's list", .0))]
    Dns(String),
}

pub fn compile(core: CoreKind, input: &CompileInput<'_>) -> Result<Compiled, CompileError> {
    input.routing.validate()?;
    input.dns.validate()?;
    match core {
        CoreKind::Xray => compile_xray(input),
        CoreKind::SingBox => compile_sing_box(input),
    }
}

/// Локальный SOCKS5 тестового ядра для полной проверки сервера.
/// Живёт несколько секунд, слушает только 127.0.0.1, со случайными портом и паролем.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeInbound<'a> {
    pub port: u16,
    pub user: &'a str,
    pub password: &'a str,
}

/// Конфиг тестового ядра: один SOCKS-вход с паролем и один выход — проверяемый
/// сервер. Без TUN, маршрутов и списков, поэтому запускается без прав администратора.
pub fn compile_probe(
    core: CoreKind,
    server: &Server,
    inbound: &ProbeInbound<'_>,
) -> Result<Value, CompileError> {
    match core {
        CoreKind::Xray => xray::probe_config(server, inbound),
        CoreKind::SingBox => sing_box::probe_config(server, inbound),
    }
}

/// Отпечаток TLS: из ссылки, а если его нет — Firefox, как у REALITY. Без него
/// sing-box шёл бы с отпечатком Go (выделяется для ТСПУ), а Xray — с Chrome, которого
/// советник считает подозрительным. У QUIC (Hysteria2, TUIC) uTLS не бывает.
fn tls_fingerprint(server: &Server, tls: &TlsSettings) -> Option<Fingerprint> {
    tls.fingerprint
        .or_else(|| (!server.protocol.is_quic()).then_some(Fingerprint::Firefox))
}

/// sing-box делает фрагментацию только для обычного TLS поверх TCP (не REALITY, не QUIC).
#[must_use]
pub fn sing_box_fragments(server: &Server) -> bool {
    matches!(server.security, Security::Tls(_)) && !server.protocol.is_quic()
}

/// Mux провайдера применяется: ядро Xray, VLESS без Vision, VMess или Trojan, не XHTTP
/// (у него свой xmux).
#[must_use]
pub fn mux_applies(server: &Server) -> bool {
    let protocol = match &server.protocol {
        Protocol::Vless { flow, .. } => !matches!(flow, Some(VlessFlow::XtlsRprxVision)),
        Protocol::Vmess { .. } | Protocol::Trojan { .. } => true,
        _ => false,
    };
    protocol
        && !matches!(server.transport, Transport::Xhttp { .. })
        && crate::core_select::select_core(server).core == CoreKind::Xray
}

fn outbound_tag(action: Action) -> &'static str {
    match action {
        Action::Proxy => TAG_PROXY,
        // Трафик zapret идёт напрямую: winws обрабатывает его на физическом интерфейсе.
        Action::Direct | Action::Zapret => TAG_DIRECT,
        Action::Block => TAG_BLOCK,
    }
}

/// `1.2.3.4` → `1.2.3.4/32`, `::1` → `::1/128`.
fn normalize_cidr(cidr: &str) -> String {
    if cidr.contains('/') {
        return cidr.to_owned();
    }
    match cidr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => format!("{cidr}/32"),
        Ok(std::net::IpAddr::V6(_)) => format!("{cidr}/128"),
        Err(_) => cidr.to_owned(),
    }
}

/// Набор правил из матчера. Неизвестные имена отсекает `RoutingPlan::validate`,
/// здесь они просто пропускаются.
fn rule_set(m: &Matcher) -> Option<RuleSetRef<'_>> {
    match m {
        Matcher::RuleSet(name) => RuleSetRef::parse(name),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_uri, Entry};
    use crate::routing::presets;

    pub(super) fn server(uri: &str) -> Server {
        match parse_uri(uri).unwrap() {
            Entry::Server(s) => *s,
            Entry::Info(_) => panic!("ожидался сервер"),
        }
    }

    pub(super) const REALITY: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?security=reality&sni=www.microsoft.com&fp=firefox&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba8&flow=xtls-rprx-vision#NL";

    pub(super) fn hybrid_plan(server: &Server) -> RoutingPlan {
        let mut plan = presets::russia_smart(Action::Proxy, presets::ListMode::Compact)
            .with_servers([server.address.clone()]);
        plan.extend(presets::zapret_youtube_discord());
        plan
    }

    /// Главный инвариант безопасности: у ядра нет ни одного слушающего порта,
    /// только TUN, и нет API.
    fn assert_no_listeners(config: &Value) {
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 1);
        let kind = inbounds[0]
            .get("protocol")
            .or_else(|| inbounds[0].get("type"))
            .unwrap();
        assert_eq!(kind, "tun");
        assert!(config.get("api").is_none());
        assert!(config.get("experimental").is_none());
        assert!(!config.to_string().contains("\"listen\""));
    }

    #[test]
    fn both_cores_have_no_listeners() {
        let s = server(REALITY);
        let plan = hybrid_plan(&s);
        let dns = DnsPlan::default();
        let input = CompileInput {
            server: &s,
            routing: &plan,
            dns: &dns,
            rule_set_dir: "C:/ProgramData/KVT/rules",
            ipv6: true,
        };
        for core in [CoreKind::Xray, CoreKind::SingBox] {
            let out = compile(core, &input).unwrap();
            assert_no_listeners(&out.config);
        }
    }

    /// IPv6 отключён в Windows: у TUN нет IPv6-интерфейса, и ядро не стартует
    /// («failed to start proxy > Element not found»), если просить у него IPv6.
    #[test]
    fn without_ipv6_tun_is_ipv4_only() {
        assert!(ipv6_enabled(None));
        assert!(ipv6_enabled(Some(0)));
        assert!(ipv6_enabled(Some(0x20))); // «предпочитать IPv4» — IPv6 работает
        assert!(!ipv6_enabled(Some(0xFF)));
        assert!(!ipv6_enabled(Some(0x10)));
        assert!(!ipv6_enabled(Some(0x32))); // у пользователя с «Element not found»

        let s = server(REALITY);
        let plan = hybrid_plan(&s);
        let dns = DnsPlan::default();
        for ipv6 in [true, false] {
            let input = CompileInput {
                server: &s,
                routing: &plan,
                dns: &dns,
                rule_set_dir: "r",
                ipv6,
            };
            let xray = compile(CoreKind::Xray, &input).unwrap().config;
            let sing = compile(CoreKind::SingBox, &input).unwrap().config;
            let tun = [
                &xray["inbounds"][0]["settings"]["gateway"],
                &xray["inbounds"][0]["settings"]["autoSystemRoutingTable"],
                &sing["inbounds"][0]["address"],
            ];
            for value in tun {
                let has_v6 = value
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v.as_str().unwrap().contains(':'));
                assert_eq!(has_v6, ipv6, "{value}");
            }
        }
    }

    #[test]
    fn invalid_routing_is_not_compiled() {
        let s = server(REALITY);
        let mut plan = RoutingPlan::new(Action::Proxy);
        plan.push(crate::routing::Rule {
            layer: crate::routing::Layer::Provider,
            matcher: Matcher::DomainSuffix("x.com".into()),
            action: Action::Zapret,
        });
        let dns = DnsPlan::default();
        let input = CompileInput {
            server: &s,
            routing: &plan,
            dns: &dns,
            rule_set_dir: "r",
            ipv6: true,
        };
        assert!(matches!(
            compile(CoreKind::Xray, &input),
            Err(CompileError::Routing(_))
        ));
    }

    #[test]
    fn dns_plan_accepts_only_catalog() {
        assert_eq!(
            DnsPlan::from_ids("yandex", "cloudflare").unwrap(),
            DnsPlan::default()
        );
        let plan = DnsPlan::from_ids("adguard", "quad9").unwrap();
        assert_eq!(plan.local, "94.140.14.14");
        assert_eq!(plan.remote_doh, "9.9.9.9");
        assert!(plan.validate().is_ok());
        // Яндекс по IP для DoH в туннеле не подходит, а чужие адреса — тем более.
        assert!(DnsPlan::from_ids("yandex", "yandex").is_err());
        assert!(DnsPlan::from_ids("evil", "cloudflare").is_err());
        let injected = DnsPlan {
            remote_doh: "1.1.1.1/dns-query?x=".into(),
            local: "77.88.8.8".into(),
            reserve_doh: None,
        };
        assert!(injected.validate().is_err());
        let injected = DnsPlan {
            reserve_doh: Some("6.6.6.6".into()),
            ..DnsPlan::default()
        };
        assert!(injected.validate().is_err());

        let s = server(REALITY);
        let plan = hybrid_plan(&s);
        let input = CompileInput {
            server: &s,
            routing: &plan,
            dns: &injected,
            rule_set_dir: "r",
            ipv6: true,
        };
        assert!(matches!(
            compile(CoreKind::Xray, &input),
            Err(CompileError::Dns(_))
        ));
    }

    #[test]
    fn cidr_normalization() {
        assert_eq!(normalize_cidr("1.2.3.4"), "1.2.3.4/32");
        assert_eq!(normalize_cidr("2001:db8::1"), "2001:db8::1/128");
        assert_eq!(normalize_cidr("10.0.0.0/8"), "10.0.0.0/8");
    }
}
