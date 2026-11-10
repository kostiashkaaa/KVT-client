//! Конфиг sing-box в формате 1.12+ (новые DNS-серверы, правила-действия).

use super::{
    normalize_cidr, outbound_tag, rule_set, CompileError, CompileInput, Compiled, TAG_DIRECT,
    TAG_PROXY, TAG_TUN, TUN_INTERFACE,
};
use crate::core_select::CoreKind;
use crate::lists::RuleSetRef;
use crate::model::{Protocol, Security, Server, Transport, VlessFlow};
use crate::routing::{Action, Matcher};
use serde_json::{json, Map, Value};

const CORE: CoreKind = CoreKind::SingBox;
const DNS_REMOTE: &str = "dns-remote";
const DNS_LOCAL: &str = "dns-local";

pub fn compile(input: &CompileInput<'_>) -> Result<Compiled, CompileError> {
    let config = json!({
        "log": { "level": "warn" },
        "dns": {
            "servers": [
                { "type": "https", "tag": DNS_REMOTE, "server": input.dns.remote_doh, "detour": TAG_PROXY },
                { "type": "udp", "tag": DNS_LOCAL, "server": input.dns.local }
            ],
            "rules": dns_rules(input),
            "final": DNS_REMOTE,
            "strategy": "prefer_ipv4"
        },
        "inbounds": [{
            "type": "tun",
            "tag": TAG_TUN,
            "interface_name": TUN_INTERFACE,
            "address": super::tun_addresses(input.ipv6),
            "mtu": 1500,
            "auto_route": true,
            // Без strict_route Windows отправляет DNS-запросы во все интерфейсы сразу.
            "strict_route": true,
            "stack": "mixed"
        }],
        "outbounds": [
            outbound(input.server)?,
            { "type": "direct", "tag": TAG_DIRECT }
        ],
        "route": {
            "rules": route_rules(input),
            "rule_set": rule_set_defs(input),
            "final": outbound_tag(input.routing.final_action),
            "auto_detect_interface": true,
            "default_domain_resolver": DNS_LOCAL
        }
    });
    Ok(Compiled {
        core: CORE,
        config,
        warnings: Vec::new(),
    })
}

/// Условие правила sing-box для одного матчера.
fn condition(m: &Matcher) -> Value {
    match m {
        Matcher::DomainSuffix(d) => json!({ "domain_suffix": [d] }),
        Matcher::Domain(d) => json!({ "domain": [d] }),
        Matcher::DomainKeyword(k) => json!({ "domain_keyword": [k] }),
        Matcher::IpCidr(c) => json!({ "ip_cidr": [normalize_cidr(c)] }),
        Matcher::RuleSet(name) => json!({ "rule_set": [name] }),
        Matcher::ProcessName(p) => json!({ "process_name": [p] }),
    }
}

fn with(mut cond: Value, key: &str, value: Value) -> Value {
    if let Value::Object(map) = &mut cond {
        map.insert(key.into(), value);
    }
    cond
}

fn route_rules(input: &CompileInput<'_>) -> Vec<Value> {
    let mut rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
    ];
    for rule in input.routing.ordered() {
        let cond = condition(&rule.matcher);
        rules.push(match rule.action {
            Action::Block => with(cond, "action", "reject".into()),
            other => with(cond, "outbound", outbound_tag(other).into()),
        });
    }
    rules
}

fn dns_rules(input: &CompileInput<'_>) -> Vec<Value> {
    input
        .routing
        .ordered()
        .into_iter()
        .filter(|r| outbound_tag(r.action) == TAG_DIRECT)
        .filter(|r| {
            matches!(
                r.matcher,
                Matcher::DomainSuffix(_)
                    | Matcher::Domain(_)
                    | Matcher::DomainKeyword(_)
                    | Matcher::RuleSet(_)
            )
        })
        .filter(|r| !rule_set(&r.matcher).is_some_and(|s| s.is_ip_only()))
        .map(|r| with(condition(&r.matcher), "server", DNS_LOCAL.into()))
        .collect()
}

fn rule_set_defs(input: &CompileInput<'_>) -> Vec<Value> {
    input
        .routing
        .rule_sets()
        .into_iter()
        .filter_map(|name| {
            let set = RuleSetRef::parse(name)?;
            Some(json!({
                "type": "local",
                "tag": name,
                "format": "binary",
                "path": format!(
                    "{}/{}",
                    input.rule_set_dir.trim_end_matches(['/', '\\']),
                    set.srs_file()
                )
            }))
        })
        .collect()
}

fn outbound(s: &Server) -> Result<Value, CompileError> {
    let mut o = Map::new();
    o.insert("tag".into(), TAG_PROXY.into());
    o.insert("server".into(), s.address.clone().into());
    o.insert("server_port".into(), s.port.into());

    match &s.protocol {
        Protocol::Vless {
            id,
            flow,
            encryption,
        } => {
            if encryption.is_some() {
                return Err(CompileError::Unsupported {
                    core: CORE,
                    feature: "VLESS Encryption",
                });
            }
            o.insert("type".into(), "vless".into());
            o.insert("uuid".into(), id.expose().into());
            if let Some(VlessFlow::XtlsRprxVision) = flow {
                o.insert("flow".into(), "xtls-rprx-vision".into());
            }
        }
        Protocol::Trojan { password } => {
            o.insert("type".into(), "trojan".into());
            o.insert("password".into(), password.expose().into());
        }
        Protocol::Shadowsocks { method, password } => {
            o.insert("type".into(), "shadowsocks".into());
            o.insert("method".into(), method.clone().into());
            o.insert("password".into(), password.expose().into());
        }
        Protocol::Hysteria2 {
            password,
            obfs,
            ports,
        } => {
            o.insert("type".into(), "hysteria2".into());
            o.insert("password".into(), password.expose().into());
            if let Some(ports) = ports {
                // `server_ports` не сочетается с `server_port`: основной порт — в списке.
                o.remove("server_port");
                o.insert("server_ports".into(), server_ports(s.port, ports).into());
            }
            if let Some(obfs) = obfs {
                o.insert(
                    "obfs".into(),
                    json!({ "type": obfs.kind, "password": obfs.password.expose() }),
                );
            }
        }
        Protocol::Vmess { id, cipher } => {
            o.insert("type".into(), "vmess".into());
            o.insert("uuid".into(), id.expose().into());
            o.insert("security".into(), cipher.clone().into());
            o.insert("alter_id".into(), 0.into());
        }
        Protocol::Tuic {
            uuid,
            password,
            congestion,
            udp_relay_mode,
        } => {
            o.insert("type".into(), "tuic".into());
            o.insert("uuid".into(), uuid.expose().into());
            o.insert("password".into(), password.expose().into());
            if let Some(c) = congestion {
                o.insert("congestion_control".into(), c.clone().into());
            }
            if let Some(m) = udp_relay_mode {
                o.insert("udp_relay_mode".into(), m.clone().into());
            }
        }
        Protocol::AnyTls { password } => {
            o.insert("type".into(), "anytls".into());
            o.insert("password".into(), password.expose().into());
        }
        Protocol::Socks { username, password } => {
            o.insert("type".into(), "socks".into());
            o.insert("version".into(), "5".into());
            if let Some(u) = username {
                o.insert("username".into(), u.expose().into());
            }
            if let Some(p) = password {
                o.insert("password".into(), p.expose().into());
            }
        }
    }

    if let Some(transport) = transport(&s.transport)? {
        o.insert("transport".into(), transport);
    }
    if let Some(tls) = tls(s) {
        o.insert("tls".into(), tls);
    }
    Ok(o.into())
}

/// `20000-30000,40000` → `["443:443", "20000:30000", "40000:40000"]` (формат sing-box).
fn server_ports(port: u16, ranges: &str) -> Vec<String> {
    let mut list: Vec<(u16, u16)> = ranges
        .split(',')
        .filter_map(|r| {
            let (a, b) = r.split_once('-').unwrap_or((r, r));
            Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
        })
        .collect();
    if !list.iter().any(|(a, b)| (*a..=*b).contains(&port)) {
        list.insert(0, (port, port));
    }
    list.into_iter().map(|(a, b)| format!("{a}:{b}")).collect()
}

fn transport(t: &Transport) -> Result<Option<Value>, CompileError> {
    Ok(match t {
        Transport::Tcp | Transport::Quic => None,
        Transport::Ws { path, host } => {
            let mut v = json!({ "type": "ws", "path": path });
            if let Some(h) = host {
                v = with(v, "headers", json!({ "Host": h }));
            }
            Some(v)
        }
        Transport::Grpc { service_name } => {
            Some(json!({ "type": "grpc", "service_name": service_name }))
        }
        Transport::HttpUpgrade { path, host } => {
            let mut v = json!({ "type": "httpupgrade", "path": path });
            if let Some(h) = host {
                v = with(v, "host", h.clone().into());
            }
            Some(v)
        }
        Transport::Xhttp { .. } => {
            return Err(CompileError::Unsupported {
                core: CORE,
                feature: "XHTTP",
            })
        }
    })
}

fn tls(s: &Server) -> Option<Value> {
    match &s.security {
        Security::None => None,
        Security::Tls(t) => {
            let mut v = json!({
                "enabled": true,
                "server_name": t.sni.clone().unwrap_or_else(|| s.address.clone()),
            });
            if !t.alpn.is_empty() {
                v = with(v, "alpn", t.alpn.clone().into());
            }
            if t.allow_insecure {
                v = with(v, "insecure", true.into());
            }
            if let Some(fp) = t.fingerprint {
                v = with(v, "utls", json!({ "enabled": true, "fingerprint": fp }));
            }
            Some(v)
        }
        Security::Reality(r) => Some(json!({
            "enabled": true,
            "server_name": r.sni,
            "utls": { "enabled": true, "fingerprint": r.fingerprint },
            "reality": { "enabled": true, "public_key": r.public_key, "short_id": r.short_id }
        })),
    }
}

/// Конфиг тестового ядра (см. `compile_probe`).
pub(super) fn probe_config(
    server: &Server,
    inbound: &super::ProbeInbound<'_>,
) -> Result<Value, CompileError> {
    Ok(json!({
        "log": { "level": "warn" },
        "dns": { "servers": [{ "type": "local", "tag": "local" }] },
        "inbounds": [{
            "type": "socks",
            "tag": "probe-in",
            "listen": "127.0.0.1",
            "listen_port": inbound.port,
            "users": [{ "username": inbound.user, "password": inbound.password }]
        }],
        "outbounds": [outbound(server)?],
        "route": { "final": TAG_PROXY, "default_domain_resolver": "local" }
    }))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{hybrid_plan, server, REALITY};
    use super::super::DnsPlan;
    use super::*;

    fn build(uri: &str) -> Compiled {
        let s = server(uri);
        let plan = hybrid_plan(&s);
        let dns = DnsPlan::default();
        compile(&CompileInput {
            server: &s,
            routing: &plan,
            dns: &dns,
            rule_set_dir: "C:\\ProgramData\\KVT\\rules\\",
            ipv6: true,
        })
        .unwrap()
    }

    #[test]
    fn reality_outbound() {
        let c = build(REALITY);
        let p = &c.config["outbounds"][0];
        assert_eq!(p["type"], "vless");
        assert_eq!(p["flow"], "xtls-rprx-vision");
        assert_eq!(
            p["tls"]["reality"]["public_key"],
            "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
        );
        assert_eq!(p["tls"]["utls"]["fingerprint"], "firefox");
        assert!(p.get("transport").is_none());
    }

    #[test]
    fn hysteria2_with_obfs() {
        let c = build(
            "hy2://secret@hy.example.com:8443?obfs=salamander&obfs-password=x&sni=hy.example.com",
        );
        let p = &c.config["outbounds"][0];
        assert_eq!(p["type"], "hysteria2");
        assert_eq!(p["obfs"]["type"], "salamander");
        assert_eq!(p["tls"]["alpn"][0], "h3");
    }

    #[test]
    fn hysteria2_port_hopping() {
        let c = build("hy2://secret@hy.example.com:443?mport=20000-30000,40000&sni=hy.example.com");
        let p = &c.config["outbounds"][0];
        assert!(p.get("server_port").is_none());
        assert_eq!(
            p["server_ports"],
            json!(["443:443", "20000:30000", "40000:40000"])
        );
        // Основной порт уже внутри диапазона — отдельно не добавляется.
        let c = build("hy2://secret@hy.example.com:20000-30000");
        assert_eq!(
            c.config["outbounds"][0]["server_ports"],
            json!(["20000:30000"])
        );
    }

    #[test]
    fn socks5_outbound() {
        let c = build("socks5://u:p@px.example.com:1080#s");
        let p = &c.config["outbounds"][0];
        assert_eq!(p["type"], "socks");
        assert_eq!(p["version"], "5");
        assert_eq!(
            (p["username"].as_str(), p["password"].as_str()),
            (Some("u"), Some("p"))
        );
        assert!(p.get("tls").is_none());
    }

    #[test]
    fn strict_route_and_rule_sets() {
        let c = build(REALITY);
        assert_eq!(c.config["inbounds"][0]["strict_route"], true);
        let sets = c.config["route"]["rule_set"].as_array().unwrap();
        assert!(sets.iter().any(|s| s["tag"] == "itdog:russia_inside"
            && s["path"] == "C:\\ProgramData\\KVT\\rules/itdog-russia_inside.srs"));
        assert!(sets.iter().any(|s| s["tag"] == "rf:geoip-ru"
            && s["path"] == "C:\\ProgramData\\KVT\\rules/rf-geoip-ru.srs"));
        assert_eq!(c.config["route"]["final"], "proxy");
        let rules = c.config["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert!(rules
            .iter()
            .any(|r| r["domain_suffix"][0] == "discord.com" && r["outbound"] == "direct"));
    }

    #[test]
    fn dns_local_only_for_direct() {
        let c = build(REALITY);
        let rules = c.config["dns"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|r| r["server"] == "dns-local"));
        assert!(rules.iter().any(|r| r["domain_suffix"][0] == "ru"));
        assert!(rules
            .iter()
            .any(|r| r["rule_set"][0] == "itdog:russia_outside"));
        assert!(!rules
            .iter()
            .any(|r| r["rule_set"][0] == "itdog:russia_inside"));
        assert!(!rules.iter().any(|r| r["rule_set"][0] == "rf:geoip-ru"));
    }

    #[test]
    fn xhttp_is_rejected() {
        let s = server(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example:443?type=xhttp&security=tls",
        );
        let plan = hybrid_plan(&s);
        let dns = DnsPlan::default();
        assert_eq!(
            compile(&CompileInput {
                server: &s,
                routing: &plan,
                dns: &dns,
                rule_set_dir: "r",
                ipv6: true,
            })
            .unwrap_err(),
            CompileError::Unsupported {
                core: CoreKind::SingBox,
                feature: "XHTTP"
            }
        );
    }
}
