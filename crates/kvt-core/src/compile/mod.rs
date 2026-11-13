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
    /// id резолвера DoH туннеля в каталоге — его первым спрашивают имена серверов
    /// (`dns::names`). Незнакомый адрес — пустая строка, тогда порядок каталога.
    pub fn remote_id(&self) -> &'static str {
        crate::dns::RESOLVERS
            .iter()
            .find(|r| r.doh.is_some_and(|d| d.ip.to_string() == self.remote_doh))
            .map_or("", |r| r.id)
    }

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
    /// Адреса имён сервера (`Server::endpoints`), которые служба нашла через DoH:
    /// ядро берёт их отсюда, а не у локального резолвера без шифрования (его запрос
    /// видел бы провайдер). Имени без адреса здесь может не быть — тогда его, как
    /// раньше, резолвит локальный резолвер.
    pub hosts: &'a [(String, Vec<std::net::IpAddr>)],
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
    disabled_components.is_none_or(|v| v & 0x10 == 0)
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
    #[error("{}", crate::trf!("настройки сервера повреждены: {}", "the server settings are damaged: {}", .0))]
    Server(#[from] crate::parser::ParseError),
    /// Для тестового ядра не нашёлся адрес имени сервера (`ProbeInbound::hosts`).
    #[error(
        "{}",
        crate::i18n::tr("адрес сервера не найден", "the server address wasn't found")
    )]
    Unresolved,
}

pub fn compile(core: CoreKind, input: &CompileInput<'_>) -> Result<Compiled, CompileError> {
    input.routing.validate()?;
    input.dns.validate()?;
    crate::parser::check_server(input.server)?;
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
    /// Адрес физического адаптера, если VPN подключён: соединение с проверяемым
    /// сервером уходит с него мимо TUN (Xray `sendThrough`, sing-box
    /// `inet4_bind_address`), иначе результат был бы «через туннель».
    pub source: Option<std::net::Ipv4Addr>,
    /// Адреса имён сервера (`Server::endpoints`), найденные через DoH
    /// (`dns::names`). Ядро берёт их отсюда и само DNS не спрашивает: иначе
    /// провайдер видел бы по запросам каждый проверяемый сервер.
    pub hosts: &'a [(String, Vec<std::net::IpAddr>)],
}

/// Имена сервера с адресами для DNS тестового ядра; IP из ссылки сюда не входят.
/// Имени без адреса быть не может — ядро спросило бы системный DNS.
fn probe_hosts(
    server: &Server,
    hosts: &[(String, Vec<std::net::IpAddr>)],
) -> Result<serde_json::Map<String, serde_json::Value>, CompileError> {
    hosts_map(server, hosts, true)
}

/// Имена сервера с адресами для DNS ядра в туннеле (см. [`CompileInput::hosts`]):
/// имя без адреса пропускается — его резолвит локальный резолвер, как раньше.
fn tunnel_hosts(
    server: &Server,
    hosts: &[(String, Vec<std::net::IpAddr>)],
) -> serde_json::Map<String, serde_json::Value> {
    hosts_map(server, hosts, false).unwrap_or_default()
}

/// Если есть IPv4, берутся только они: IPv6 без доступа в сеть сломал бы
/// соединение. `strict` — имя без адреса означает ошибку.
fn hosts_map(
    server: &Server,
    hosts: &[(String, Vec<std::net::IpAddr>)],
    strict: bool,
) -> Result<serde_json::Map<String, serde_json::Value>, CompileError> {
    let mut map = serde_json::Map::new();
    for name in server.endpoints() {
        let literal = name.trim_start_matches('[').trim_end_matches(']');
        if literal.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        let found = hosts
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(&name))
            .map(|(_, ips)| ips.as_slice())
            .filter(|ips| !ips.is_empty());
        let ips = match found {
            Some(ips) => ips,
            None if strict => return Err(CompileError::Unresolved),
            None => continue,
        };
        let v4 = ips.iter().any(std::net::IpAddr::is_ipv4);
        let list = ips
            .iter()
            .filter(|ip| ip.is_ipv4() == v4)
            .map(|ip| serde_json::Value::from(ip.to_string()))
            .collect();
        map.insert(name, serde_json::Value::Array(list));
    }
    Ok(map)
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
            hosts: &[],
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
                hosts: &[],
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
            hosts: &[],
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
            hosts: &[],
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

    const NAMED: &str = "trojan://secret@Tr.Example.com:443?sni=tr.example.com#t";

    fn probe(
        core: CoreKind,
        uri: &str,
        hosts: &[(String, Vec<std::net::IpAddr>)],
    ) -> Result<serde_json::Value, CompileError> {
        let inbound = ProbeInbound {
            port: 41_000,
            user: "u",
            password: "p",
            source: None,
            hosts,
        };
        compile_probe(core, &server(uri), &inbound)
    }

    /// Имя сервера тестовое ядро берёт из найденных через DoH адресов, а не из DNS.
    #[test]
    fn probe_core_gets_server_name_from_hosts() {
        let hosts = vec![(
            "tr.example.com".to_string(),
            vec![
                "2001:db8::1".parse().unwrap(),
                "203.0.113.5".parse().unwrap(),
            ],
        )];
        let x = probe(CoreKind::Xray, NAMED, &hosts).unwrap();
        // Только IPv4, если он есть; имя — как в ссылке.
        assert_eq!(
            x["dns"]["hosts"]["Tr.Example.com"],
            serde_json::json!(["203.0.113.5"])
        );
        assert_eq!(
            x["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
            "ForceIP"
        );
        let s = probe(CoreKind::SingBox, NAMED, &hosts).unwrap();
        let dns = &s["dns"]["servers"][0];
        assert_eq!(dns["type"], "hosts");
        assert_eq!(
            dns["predefined"]["Tr.Example.com"],
            serde_json::json!(["203.0.113.5"])
        );
        assert_eq!(s["route"]["default_domain_resolver"], dns["tag"]);
    }

    /// Без адреса имени конфиг не собирается: ядро спросило бы системный DNS.
    #[test]
    fn probe_without_address_is_refused() {
        for core in [CoreKind::Xray, CoreKind::SingBox] {
            assert!(matches!(
                probe(core, NAMED, &[]),
                Err(CompileError::Unresolved)
            ));
            let empty = vec![("tr.example.com".to_string(), Vec::new())];
            assert!(matches!(
                probe(core, NAMED, &empty),
                Err(CompileError::Unresolved)
            ));
        }
    }

    /// В туннеле имя сервера — найденными службой через DoH адресами; без адреса —
    /// как раньше, локальным резолвером.
    #[test]
    fn tunnel_core_gets_server_name_from_hosts() {
        let s = server(NAMED);
        let plan = hybrid_plan(&s);
        let dns = DnsPlan::default();
        let hosts = vec![(
            "tr.example.com".to_string(),
            vec!["203.0.113.5".parse().unwrap()],
        )];
        let mut input = CompileInput {
            server: &s,
            routing: &plan,
            dns: &dns,
            rule_set_dir: "C:/ProgramData/KVT/rules",
            ipv6: true,
            hosts: &hosts,
        };
        let x = compile(CoreKind::Xray, &input).unwrap().config;
        assert_eq!(
            x["dns"]["hosts"]["Tr.Example.com"],
            serde_json::json!(["203.0.113.5"])
        );
        let sb = compile(CoreKind::SingBox, &input).unwrap().config;
        let servers = sb["dns"]["servers"].as_array().unwrap();
        let hosts_server = servers.iter().find(|v| v["type"] == "hosts").unwrap();
        assert_eq!(
            hosts_server["predefined"]["Tr.Example.com"],
            serde_json::json!(["203.0.113.5"])
        );
        assert_eq!(sb["outbounds"][0]["domain_resolver"], hosts_server["tag"]);

        input.hosts = &[];
        let x = compile(CoreKind::Xray, &input).unwrap().config;
        assert!(x["dns"].get("hosts").is_none());
        let sb = compile(CoreKind::SingBox, &input).unwrap().config;
        assert!(sb["outbounds"][0].get("domain_resolver").is_none());
    }

    #[test]
    fn remote_resolver_id_from_plan() {
        assert_eq!(
            DnsPlan::from_ids("yandex", "quad9").unwrap().remote_id(),
            "quad9"
        );
        assert_eq!(DnsPlan::default().remote_id(), "cloudflare");
        let odd = DnsPlan {
            remote_doh: "192.0.2.1".into(),
            ..DnsPlan::default()
        };
        assert_eq!(odd.remote_id(), "");
    }

    /// Сервер по IP: резолвить нечего, DNS ядра не трогаем.
    #[test]
    fn probe_by_ip_needs_no_hosts() {
        let x = probe(CoreKind::Xray, REALITY, &[]).unwrap();
        assert!(x.get("dns").is_none());
        let s = probe(CoreKind::SingBox, REALITY, &[]).unwrap();
        assert_eq!(s["dns"]["servers"][0]["type"], "local");
    }
}
