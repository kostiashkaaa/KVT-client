use super::{
    normalize_cidr, outbound_tag, rule_set, CompileError, CompileInput, Compiled, TAG_BLOCK,
    TAG_DIRECT, TAG_PROXY, TAG_TUN, TUN_INTERFACE,
};
use crate::core_select::CoreKind;
use crate::model::{Protocol, Security, Server, Transport, VlessFlow};
use crate::routing::presets::PRIVATE_NETWORKS;
use crate::routing::Matcher;
use serde_json::{json, Map, Value};

const CORE: CoreKind = CoreKind::Xray;
const TAG_DNS: &str = "dns-out";

pub fn compile(input: &CompileInput<'_>) -> Result<Compiled, CompileError> {
    let mut dns_servers = vec![
        json!(format!("https://{}/dns-query", input.dns.remote_doh)),
        // skipFallback: локальный резолвер никогда не становится запасным для
        // доменов, которые идут через VPN, — иначе их видел бы провайдер.
        json!({
            "address": input.dns.local,
            "domains": direct_domains(input),
            "skipFallback": true
        }),
    ];
    // Запасной DoH через туннель: Xray переходит к нему, если основной не ответил.
    if let Some(reserve) = &input.dns.reserve_doh {
        dns_servers.push(json!(format!("https://{reserve}/dns-query")));
    }
    let mut config = json!({
        // Журнал доступа («accepted …» на каждое соединение) выключен: в журнале ядра
        // остаётся 200 строк, и он вытеснял настоящие ошибки — в экспорте диагностики их
        // не было видно.
        "log": { "loglevel": "warning", "access": "none" },
        "dns": {
            "servers": dns_servers,
            "queryStrategy": "UseIPv4"
        },
        "inbounds": [{
            "tag": TAG_TUN,
            "protocol": "tun",
            "settings": {
                "name": TUN_INTERFACE,
                "mtu": 1500,
                "gateway": super::tun_addresses(input.ipv6),
                // DNS интерфейса: запросы системы уходят в TUN и перехватываются правилом порта 53.
                "dns": [input.dns.remote_doh],
                "autoSystemRoutingTable": if input.ipv6 { vec!["0.0.0.0/0", "::/0"] } else { vec!["0.0.0.0/0"] },
                // Трафик самого Xray к серверу идёт через физический интерфейс — без петли.
                "autoOutboundsInterface": "auto"
            },
            // Имя из sniffing заменяет адрес назначения: серверу уходит имя сайта, а не
            // IP, как у Happ и v2rayN. Иначе доменные правила провайдера (3x-ui:
            // `geosite:google → warp`) срабатывали, только если сервер сам узнал имя, —
            // и Gemini выходил с IP сервера, который Google считает российским
            // (2026-11-14). Локальную сеть не трогаем: имя устройства (`nas.local`)
            // нигде не резолвится, и правило «частные сети напрямую» его бы не узнало.
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": false,
                "ipsExcluded": PRIVATE_NETWORKS
            }
        }],
        "outbounds": [
            server_outbound(input.server)?,
            // Прямой выход получает имя — адрес берёт встроенный DNS (ответ на запрос
            // программы уже в его кэше), а не системный: тот ушёл бы обратно в TUN.
            { "tag": TAG_DIRECT, "protocol": "freedom", "streamSettings": { "sockopt": { "domainStrategy": "UseIPv4" } } },
            { "tag": TAG_BLOCK, "protocol": "blackhole" },
            { "tag": TAG_DNS, "protocol": "dns" }
        ],
        // IPOnDemand: правило по IP (`geoip-ru`, «Свои сайты», частные сети) для
        // соединения с именем проверяется по адресу из встроенного DNS — в своём месте
        // порядка правил. IPIfNonMatch не годится: последнее правило «всё остальное»
        // совпадает всегда, и до проверки по IP дело бы не дошло.
        "routing": {
            "domainStrategy": "IPOnDemand",
            "rules": rules(input)
        }
    });
    // Имя сервера — адресами, которые служба нашла через DoH: встроенный DNS ответит
    // из `hosts` и локальный резолвер о нём не спросит.
    let hosts = super::tunnel_hosts(input.server, input.hosts);
    if !hosts.is_empty() {
        config["dns"]["hosts"] = Value::Object(hosts);
    }
    Ok(Compiled {
        core: CORE,
        config,
        warnings: Vec::new(),
    })
}

/// Домены, которые резолвятся локальным DNS: прямые правила и адрес сервера.
fn direct_domains(input: &CompileInput<'_>) -> Vec<String> {
    let server = input
        .server
        .endpoints()
        .into_iter()
        .filter(|h| h.parse::<std::net::IpAddr>().is_err())
        .map(|h| format!("full:{h}"));
    let rules = input
        .routing
        .ordered()
        .into_iter()
        .filter(|r| super::outbound_tag(r.action) == TAG_DIRECT)
        .filter_map(|r| match &r.matcher {
            Matcher::DomainSuffix(d) => Some(format!("domain:{d}")),
            Matcher::Domain(d) => Some(format!("full:{d}")),
            m => rule_set(m)
                .filter(|s| !s.is_ip_only())
                .map(|s| s.xray_expr()),
        });
    server.chain(rules).collect()
}

/// Выход к VPN-серверу в режиме TUN. Имя сервера Xray резолвит встроенным DNS —
/// локальным резолвером (`direct_domains`) от имени xray.exe, как sing-box
/// (`default_domain_resolver`). По умолчанию Xray спрашивает системный DNS: запрос
/// уходит от службы DNS Windows, а её запросы мимо туннеля служба блокирует
/// (`wfp::DnsGuard`) — имя сервера резолвилось бы через сам туннель.
fn server_outbound(s: &Server) -> Result<Value, CompileError> {
    Ok(with_domain_strategy(outbound(s)?, "UseIPv4"))
}

/// Имя сервера (и сервера загрузки XHTTP) — встроенным DNS Xray, а не системным.
fn with_domain_strategy(mut out: Value, strategy: &str) -> Value {
    let local_dns = json!({ "domainStrategy": strategy });
    out["streamSettings"]["sockopt"] = local_dns.clone();
    // Сервер загрузки XHTTP — свой `streamSettings` со своим адресом.
    if let Some(download) = out
        .pointer_mut("/streamSettings/xhttpSettings/extra/downloadSettings")
        .filter(|d| d.is_object())
    {
        download["sockopt"] = local_dns;
    }
    out
}

fn rules(input: &CompileInput<'_>) -> Vec<Value> {
    let mut out = vec![
        // DNS-запросы из TUN — во встроенный DNS Xray (DoH через туннель).
        json!({ "inboundTag": [TAG_TUN], "port": "53", "outboundTag": TAG_DNS }),
        // Локальный резолвер всегда напрямую, иначе прямые домены резолвились бы через VPN.
        json!({ "ip": [normalize_cidr(&input.dns.local)], "outboundTag": TAG_DIRECT }),
    ];
    for rule in input.routing.ordered() {
        let tag = outbound_tag(rule.action);
        let rule_json = match &rule.matcher {
            Matcher::DomainSuffix(d) => {
                json!({ "domain": [format!("domain:{d}")], "outboundTag": tag })
            }
            Matcher::Domain(d) => json!({ "domain": [format!("full:{d}")], "outboundTag": tag }),
            Matcher::DomainKeyword(k) => {
                json!({ "domain": [format!("keyword:{k}")], "outboundTag": tag })
            }
            Matcher::IpCidr(c) => json!({ "ip": [normalize_cidr(c)], "outboundTag": tag }),
            m @ Matcher::RuleSet(_) => match rule_set(m) {
                Some(s) if s.is_ip_only() => json!({ "ip": [s.xray_expr()], "outboundTag": tag }),
                Some(s) => json!({ "domain": [s.xray_expr()], "outboundTag": tag }),
                None => continue,
            },
            Matcher::ProcessName(p) => json!({ "process": [p], "outboundTag": tag }),
        };
        out.push(rule_json);
    }
    // Xray не знает final — последнее правило ловит всё остальное.
    out.push(
        json!({ "network": "tcp,udp", "outboundTag": outbound_tag(input.routing.final_action) }),
    );
    out
}

fn outbound(s: &Server) -> Result<Value, CompileError> {
    let (protocol, settings) = match &s.protocol {
        Protocol::Vless {
            id,
            flow,
            encryption,
        } => {
            let mut user = Map::new();
            user.insert("id".into(), id.expose().into());
            user.insert(
                "encryption".into(),
                encryption.as_deref().unwrap_or("none").into(),
            );
            if let Some(VlessFlow::XtlsRprxVision) = flow {
                user.insert("flow".into(), "xtls-rprx-vision".into());
            }
            (
                "vless",
                json!({ "vnext": [{ "address": s.address, "port": s.port, "users": [user] }] }),
            )
        }
        Protocol::Trojan { password } => (
            "trojan",
            json!({ "servers": [{ "address": s.address, "port": s.port, "password": password.expose() }] }),
        ),
        Protocol::Shadowsocks { method, password } => (
            "shadowsocks",
            json!({ "servers": [{
                "address": s.address, "port": s.port, "method": method, "password": password.expose()
            }] }),
        ),
        Protocol::Vmess { id, cipher } => (
            "vmess",
            json!({ "vnext": [{ "address": s.address, "port": s.port, "users": [{
                "id": id.expose(), "security": cipher
            }] }] }),
        ),
        Protocol::Hysteria2 { .. } => {
            return Err(CompileError::Unsupported {
                core: CORE,
                feature: crate::i18n::tr(
                    "Hysteria2 (используйте sing-box)",
                    "Hysteria2 (use sing-box)",
                ),
            })
        }
        Protocol::Tuic { .. } => {
            return Err(CompileError::Unsupported {
                core: CORE,
                feature: crate::i18n::tr("TUIC (используйте sing-box)", "TUIC (use sing-box)"),
            })
        }
        Protocol::AnyTls { .. } => {
            return Err(CompileError::Unsupported {
                core: CORE,
                feature: crate::i18n::tr("AnyTLS (используйте sing-box)", "AnyTLS (use sing-box)"),
            })
        }
        Protocol::Socks { .. } => {
            return Err(CompileError::Unsupported {
                core: CORE,
                feature: crate::i18n::tr("SOCKS5 (используйте sing-box)", "SOCKS5 (use sing-box)"),
            })
        }
        Protocol::Http { .. } => {
            return Err(CompileError::Unsupported {
                core: CORE,
                feature: crate::i18n::tr(
                    "HTTP-прокси (используйте sing-box)",
                    "HTTP proxy (use sing-box)",
                ),
            })
        }
    };
    let mut out = json!({
        "tag": TAG_PROXY,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream_settings(s)?
    });
    if let Some(n) = s.mux.filter(|_| super::mux_applies(s)) {
        out["mux"] = json!({ "enabled": true, "concurrency": n });
    }
    Ok(out)
}

fn stream_settings(s: &Server) -> Result<Value, CompileError> {
    let mut stream = Map::new();
    let (network, key, value) = match &s.transport {
        Transport::Tcp => ("raw", None, Value::Null),
        Transport::Ws { path, host } => (
            "ws",
            Some("wsSettings"),
            json!({ "path": path, "host": host }),
        ),
        Transport::Grpc { service_name } => (
            "grpc",
            Some("grpcSettings"),
            json!({ "serviceName": service_name }),
        ),
        Transport::HttpUpgrade { path, host } => (
            "httpupgrade",
            Some("httpupgradeSettings"),
            json!({ "path": path, "host": host }),
        ),
        Transport::Xhttp {
            path,
            host,
            mode,
            extra,
        } => {
            let mut v =
                json!({ "path": path, "host": host, "mode": mode.as_deref().unwrap_or("auto") });
            // `extra` — заново через белый список (`parser::xhttp_extra`): модель
            // приходит в службу от окна, которому служба не доверяет.
            if let Some(extra) = extra
                .as_deref()
                .and_then(crate::parser::sanitized_extra)
                .and_then(|e| serde_json::from_str::<Value>(&e).ok())
            {
                v["extra"] = extra;
            }
            ("xhttp", Some("xhttpSettings"), v)
        }
        Transport::Quic => {
            return Err(CompileError::Unsupported {
                core: CORE,
                feature: crate::i18n::tr("QUIC-транспорт", "QUIC transport"),
            })
        }
    };
    stream.insert("network".into(), network.into());
    if let Some(key) = key {
        stream.insert(key.into(), strip_nulls(value));
    }

    match &s.security {
        Security::None => {
            stream.insert("security".into(), "none".into());
        }
        Security::Tls(tls) => {
            let mut t = Map::new();
            t.insert(
                "serverName".into(),
                tls.sni.clone().unwrap_or_else(|| s.address.clone()).into(),
            );
            if !tls.alpn.is_empty() {
                t.insert("alpn".into(), tls.alpn.clone().into());
            }
            if let Some(fp) = super::tls_fingerprint(s, tls) {
                t.insert(
                    "fingerprint".into(),
                    serde_json::to_value(fp).unwrap_or(Value::Null),
                );
            }
            if tls.allow_insecure {
                t.insert("allowInsecure".into(), true.into());
            }
            if let Some(ech) = &tls.ech {
                t.insert("echConfigList".into(), ech.clone().into());
            }
            stream.insert("security".into(), "tls".into());
            stream.insert("tlsSettings".into(), t.into());
        }
        Security::Reality(r) => {
            stream.insert("security".into(), "reality".into());
            stream.insert(
                "realitySettings".into(),
                strip_nulls(json!({
                    "serverName": r.sni,
                    "publicKey": r.public_key,
                    "shortId": r.short_id,
                    "fingerprint": r.fingerprint,
                    "spiderX": r.spider_x,
                })),
            );
        }
    }
    if let Some(f) = &s.fragment {
        // Первый в списке — ближайший к TCP слой: куски уходят уже после TLS/REALITY.
        stream.insert(
            "finalmask".into(),
            json!({ "tcp": [{ "type": "fragment", "settings": {
                "packets": f.packets, "length": f.length, "delay": f.delay
            } }] }),
        );
    }
    Ok(stream.into())
}

fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            Value::Object(map.into_iter().filter(|(_, v)| !v.is_null()).collect())
        }
        other => other,
    }
}

/// Конфиг тестового ядра (см. `compile_probe`).
pub(super) fn probe_config(
    server: &Server,
    inbound: &super::ProbeInbound<'_>,
) -> Result<Value, CompileError> {
    let hosts = super::probe_hosts(server, inbound.hosts)?;
    let mut config = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "probe-in",
            "listen": "127.0.0.1",
            "port": inbound.port,
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{ "user": inbound.user, "pass": inbound.password }],
                "udp": false
            }
        }],
        "outbounds": [probe_outbound(server, inbound, !hosts.is_empty())?]
    });
    // Имена сервера — из найденных через DoH адресов. Встроенный DNS без серверов
    // спросил бы систему, но до него не доходит: все имена есть в `hosts`.
    if !hosts.is_empty() {
        config["dns"] = json!({ "hosts": hosts });
    }
    Ok(config)
}

fn probe_outbound(
    server: &Server,
    inbound: &super::ProbeInbound<'_>,
    named: bool,
) -> Result<Value, CompileError> {
    let mut out = outbound(server)?;
    // `ForceIP`: адрес только из встроенного DNS, без отката на системный.
    if named {
        out = with_domain_strategy(out, "ForceIP");
    }
    if let Some(source) = inbound.source {
        out["sendThrough"] = source.to_string().into();
    }
    Ok(out)
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
            rule_set_dir: "r",
            ipv6: true,
            hosts: &[],
        })
        .unwrap()
    }

    #[test]
    fn reality_vision_outbound() {
        let c = build(REALITY);
        let proxy = &c.config["outbounds"][0];
        assert_eq!(proxy["protocol"], "vless");
        assert_eq!(
            proxy["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(proxy["streamSettings"]["security"], "reality");
        assert_eq!(
            proxy["streamSettings"]["realitySettings"]["fingerprint"],
            "firefox"
        );
        assert!(proxy["streamSettings"]["realitySettings"]
            .get("spiderX")
            .is_none());
    }

    #[test]
    fn routing_order_and_final() {
        let c = build(REALITY);
        let rules = c.config["routing"]["rules"].as_array().unwrap();
        // Адрес сервера — в системном слое, раньше любых правил пресета и zapret.
        let server_rule = rules
            .iter()
            .position(|r| r["ip"][0] == "203.0.113.10/32")
            .unwrap();
        let first_preset = rules
            .iter()
            .position(|r| r["domain"][0] == "ext:itdog-geosite.dat:russia-outside")
            .unwrap();
        assert!(server_rule < first_preset);
        assert_eq!(rules[server_rule]["outboundTag"], "direct");
        // YouTube в гибриде идёт напрямую (его обрабатывает winws).
        assert!(rules
            .iter()
            .any(|r| r["domain"][0] == "domain:youtube.com" && r["outboundTag"] == "direct"));
        assert!(rules.iter().any(|r| r["ip"][0] == "geoip:ru"));
        let last = rules.last().unwrap();
        assert_eq!(last["network"], "tcp,udp");
        assert_eq!(last["outboundTag"], "proxy");
    }

    #[test]
    fn xhttp_settings() {
        let c = build("vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?type=xhttp&security=tls&path=%2Fx&fp=edge");
        let st = &c.config["outbounds"][0]["streamSettings"];
        assert_eq!(st["network"], "xhttp");
        assert_eq!(st["xhttpSettings"]["path"], "/x");
        assert_eq!(st["xhttpSettings"]["mode"], "auto");
        assert!(st["xhttpSettings"].get("host").is_none());
        assert_eq!(st["tlsSettings"]["serverName"], "cdn.example.com");
    }

    #[test]
    fn reserve_doh_goes_last_and_local_never_falls_back() {
        let dns = DnsPlan::from_ids("yandex", "cloudflare").unwrap();
        assert_eq!(dns.reserve_doh.as_deref(), Some("8.8.8.8"));
        dns.validate().unwrap();
        let s = server(REALITY);
        let routing = hybrid_plan(&s);
        let c = compile(&CompileInput {
            server: &s,
            routing: &routing,
            dns: &dns,
            rule_set_dir: "rules",
            ipv6: true,
            hosts: &[],
        })
        .unwrap();
        let servers = c.config["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0], "https://1.1.1.1/dns-query");
        assert_eq!(servers[1]["skipFallback"], true);
        assert_eq!(servers[2], "https://8.8.8.8/dns-query");
    }

    #[test]
    fn direct_domains_resolve_locally() {
        let c = build(REALITY);
        let local = &c.config["dns"]["servers"][1];
        assert_eq!(local["address"], "77.88.8.8");
        let domains = local["domains"].as_array().unwrap();
        assert!(domains.contains(&"domain:ru".into()));
        assert!(domains.contains(&"ext:itdog-geosite.dat:russia-outside".into()));
        assert!(!domains.contains(&"ext:itdog-geosite.dat:russia-inside".into()));
    }

    #[test]
    fn provider_tuning_reaches_xray() {
        let c = build("vless://b831381d-6324-4d53-ad4f-8cda48b30811@up.example.com:443?type=xhttp&security=tls&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&fragment=tlshello,100-200,10-20#x");
        let st = &c.config["outbounds"][0]["streamSettings"];
        assert_eq!(st["xhttpSettings"]["extra"]["xPaddingBytes"], "100-1000");
        assert_eq!(st["finalmask"]["tcp"][0]["type"], "fragment");
        assert_eq!(st["finalmask"]["tcp"][0]["settings"]["length"], "100-200");
        // Без fp — Firefox, а не Chrome по умолчанию Xray.
        assert_eq!(st["tlsSettings"]["fingerprint"], "firefox");

        let ws = build("vless://b831381d-6324-4d53-ad4f-8cda48b30811@w.example.com:443?type=ws&security=tls&mux=4#w");
        assert_eq!(ws.config["outbounds"][0]["mux"]["concurrency"], 4);
        // С Vision mux не включается.
        let mut reality = server(REALITY);
        reality.mux = Some(8);
        assert!(!crate::compile::mux_applies(&reality));
        assert!(outbound(&reality).unwrap().get("mux").is_none());
        assert!(!reality.warnings().is_empty());
    }

    /// Серверу уходит имя сайта (как у Happ и v2rayN), а правила по IP работают:
    /// адрес для них — из встроенного DNS, в своём месте порядка правил.
    #[test]
    fn server_gets_site_name_and_ip_rules_still_apply() {
        let c = build(REALITY).config;
        let sniffing = &c["inbounds"][0]["sniffing"];
        assert_eq!(sniffing["routeOnly"], false);
        // Локальная сеть — по IP: имя устройства нигде не резолвится.
        let excluded = sniffing["ipsExcluded"].as_array().unwrap();
        assert!(excluded.iter().any(|v| v == "192.168.0.0/16"));
        assert_eq!(c["routing"]["domainStrategy"], "IPOnDemand");
        let direct = c["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == TAG_DIRECT)
            .unwrap();
        assert_eq!(
            direct["streamSettings"]["sockopt"]["domainStrategy"],
            "UseIPv4"
        );
    }

    /// Имя сервера (и сервера загрузки XHTTP) — встроенным DNS через локальный
    /// резолвер, а не системным: системный DNS мимо туннеля служба закрывает.
    #[test]
    fn server_name_resolves_by_local_dns() {
        let extra = percent_encoding::utf8_percent_encode(
            r#"{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"dl.example.com"}}}"#,
            percent_encoding::NON_ALPHANUMERIC,
        );
        let c = build(&format!("vless://b831381d-6324-4d53-ad4f-8cda48b30811@up.example.com:443?type=xhttp&security=tls&path=%2Fx&extra={extra}#x"));
        let st = &c.config["outbounds"][0]["streamSettings"];
        assert_eq!(st["sockopt"]["domainStrategy"], "UseIPv4");
        assert_eq!(
            st["xhttpSettings"]["extra"]["downloadSettings"]["sockopt"]["domainStrategy"],
            "UseIPv4"
        );
        let domains = c.config["dns"]["servers"][1]["domains"].as_array().unwrap();
        assert!(domains.contains(&"full:up.example.com".into()));
        assert!(domains.contains(&"full:dl.example.com".into()));

        // IP в список доменов не попадает; у других транспортов лишних ключей нет.
        let c = build(REALITY);
        let domains = c.config["dns"]["servers"][1]["domains"].as_array().unwrap();
        assert!(!domains.iter().any(|d| d == "full:203.0.113.10"));
        let st = &c.config["outbounds"][0]["streamSettings"];
        assert!(st.get("xhttpSettings").is_none());
        assert_eq!(st["sockopt"]["domainStrategy"], "UseIPv4");
    }

    #[test]
    fn hysteria2_is_rejected() {
        let s = server("hy2://p@h.example.com:443");
        let plan = hybrid_plan(&s);
        let dns = DnsPlan::default();
        assert!(matches!(
            compile(&CompileInput {
                server: &s,
                routing: &plan,
                dns: &dns,
                rule_set_dir: "r",
                ipv6: true,
                hosts: &[],
            }),
            Err(CompileError::Unsupported { .. })
        ));
    }
}
