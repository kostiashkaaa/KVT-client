//! Тесты переноса: сборка ссылок из профилей v2rayN, NekoRay, Throne и Hiddify.

use super::*;
use serde_json::{json, Map, Value};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PBK: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn server(link: &str) -> crate::Server {
    match parse_uri(link).unwrap() {
        Entry::Server(s) => *s,
        Entry::Info(_) => panic!("info"),
    }
}

#[test]
fn v2rayn_new_schema_vless_reality() {
    let row = obj(json!({
        "ConfigType": 5, "Remarks": "NL #1", "Address": "nl.example.com", "Port": 443,
        "Id": UUID, "Network": "raw", "StreamSecurity": "reality", "Sni": "www.microsoft.com",
        "Fingerprint": "chrome", "PublicKey": PBK, "ShortId": "6ba8",
        "ProtoExtra": "{\"Flow\":\"xtls-rprx-vision\",\"VlessEncryption\":\"none\"}",
        "TransportExtra": "{}"
    }));
    let link = v2rayn_profile(&row).unwrap();
    let s = server(&link);
    assert_eq!(s.name, "NL #1");
    assert_eq!(s.address, "nl.example.com");
    assert_eq!(s.visible_sni(), Some("www.microsoft.com"));
    assert!(link.contains("flow=xtls-rprx-vision"));
}

#[test]
fn v2rayn_old_schema_ws_tls_and_trojan() {
    let row = obj(json!({
        "ConfigType": 5, "Remarks": "WS", "Address": "ws.example.com", "Port": "8443",
        "Id": UUID, "Security": "none", "Network": "ws", "RequestHost": "cdn.example.com",
        "Path": "/ray?ed=2048", "StreamSecurity": "tls", "Sni": "cdn.example.com", "AllowInsecure": "false"
    }));
    let s = server(&v2rayn_profile(&row).unwrap());
    assert!(format!("{:?}", s.transport).contains("/ray?ed=2048"));

    let trojan = obj(json!({
        "ConfigType": 6, "Remarks": "T", "Address": "t.example.com", "Port": 443,
        "Id": "p@ss:word", "Network": "tcp", "StreamSecurity": "tls"
    }));
    assert!(server(&v2rayn_profile(&trojan).unwrap()).name == "T");
}

#[test]
fn v2rayn_shadowsocks_and_hysteria2() {
    let ss = obj(json!({
        "ConfigType": 3, "Remarks": "SS", "Address": "1.2.3.4", "Port": 8388,
        "Id": "secret", "Security": "chacha20-ietf-poly1305"
    }));
    assert_eq!(server(&v2rayn_profile(&ss).unwrap()).address, "1.2.3.4");

    let hy = obj(json!({
        "ConfigType": 7, "Remarks": "HY", "Address": "hy.example.com", "Port": 443,
        "Id": "pw", "Sni": "hy.example.com", "Path": "obfs-secret"
    }));
    let link = v2rayn_profile(&hy).unwrap();
    assert!(link.contains("obfs=salamander") && link.contains("obfs-password=obfs-secret"));
    server(&link);
}

#[test]
fn v2rayn_vmess_and_unknown_are_skipped_with_reason() {
    assert_eq!(
        v2rayn_profile(&obj(json!({"ConfigType": 1, "Address": "a", "Port": 1}))),
        Err("VMess не поддерживается")
    );
    assert!(v2rayn_profile(&obj(json!({"ConfigType": 9}))).is_err());
    assert!(v2rayn_profile(&obj(
        json!({"ConfigType": 5, "Address": "", "Port": 443, "Id": UUID})
    ))
    .is_err());
}

#[test]
fn nekoray_profiles() {
    let v = json!({"type": "vless", "id": 3, "gid": 0, "bean": {
        "name": "Neko", "addr": "2001:db8::1", "port": 443, "pass": UUID, "flow": "xtls-rprx-vision",
        "stream": {"net": "tcp", "sec": "tls", "sni": "www.microsoft.com", "utls": "firefox",
                   "pbk": PBK, "sid": "6ba8"}
    }});
    let (name, link) = nekoray_profile(&v).unwrap();
    assert_eq!(name, "Neko");
    assert!(link.contains("@[2001:db8::1]:443"));
    assert!(link.contains("security=reality"));
    server(&link);

    let ss = json!({"type": "shadowsocks", "bean": {"name": "S", "addr": "s.example.com", "port": 8388,
        "method": "aes-256-gcm", "pass": "pw"}});
    server(&nekoray_profile(&ss).unwrap().1);
    let plugin =
        json!({"type": "shadowsocks", "bean": {"addr": "s", "port": 1, "plugin": "obfs-local"}});
    assert!(nekoray_profile(&plugin).is_err());
}

#[test]
fn singbox_outbounds() {
    let v = json!({"type": "vless", "tag": "proxy", "server": "sb.example.com", "server_port": 443,
        "uuid": UUID, "flow": "xtls-rprx-vision",
        "tls": {"enabled": true, "server_name": "www.microsoft.com",
                "utls": {"enabled": true, "fingerprint": "chrome"},
                "reality": {"enabled": true, "public_key": PBK, "short_id": "6ba8"}}});
    let s = server(&singbox_outbound(&v, "Throne NL").unwrap());
    assert_eq!(s.name, "Throne NL");

    let ws = json!({"type": "trojan", "server": "t.example.com", "server_port": 443, "password": "pw",
        "tls": {"enabled": true, "server_name": "t.example.com"},
        "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "t.example.com"}}});
    let s = server(&singbox_outbound(&ws, "").unwrap());
    assert_eq!(s.address, "t.example.com");

    let hy = json!({"type": "hysteria2", "server": "h.example.com", "server_port": 443, "password": "pw",
        "tls": {"enabled": true, "server_name": "h.example.com"},
        "obfs": {"type": "salamander", "password": "x"}});
    server(&singbox_outbound(&hy, "H").unwrap());

    assert!(singbox_outbound(&json!({"type": "tuic"}), "").is_err());
    assert!(is_service_outbound(&json!({"type": "direct"})));
}

#[test]
fn collected_dedups_and_hides_secrets_in_preview() {
    let mut c = Collected::new(Client::V2rayN, r"C:\v2rayN");
    c.add_subscription("Мой VPN", "https://sub.example.com/api/SECRET-TOKEN");
    c.add_subscription("Дубль", "https://sub.example.com/api/SECRET-TOKEN");
    c.add_subscription("Старая", "http://old.example.com/sub");
    c.add_subscription("Мусор", "not a url");
    let row = obj(json!({"ConfigType": 1}));
    c.add_server("vmess", v2rayn_profile(&row));
    c.add_server("vmess2", v2rayn_profile(&row));
    let v = json!({"type": "trojan", "server": "t.example.com", "server_port": 443, "password": "SECRET-PASS"});
    c.add_server("T", singbox_outbound(&v, "T"));
    c.add_server("T", singbox_outbound(&v, "T"));

    assert_eq!(c.subscriptions.len(), 1);
    assert_eq!(c.servers.len(), 1);
    let p = c.preview();
    let shown = serde_json::to_string(&p).unwrap();
    assert!(!shown.contains("SECRET"), "{shown}");
    assert_eq!(p.subscriptions[0].host, "sub.example.com");
    assert_eq!(p.servers[0].protocol, "Trojan");
    assert!(shown.contains("\"client\":\"v2rayn\""));
    assert!(p
        .skipped
        .iter()
        .any(|s| s.reason == "VMess не поддерживается" && s.count == 2));
    assert!(p
        .skipped
        .iter()
        .any(|s| s.reason == "подписка по незащищённому http"));
}

#[test]
fn names_are_cleaned() {
    assert_eq!(clean_name("  \u{7}\n "), "Без названия");
    assert_eq!(clean_name(&"x".repeat(500)).len(), MAX_NAME);
}
