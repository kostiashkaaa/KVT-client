//! WireGuard и AmneziaWG в конфиге sing-box. С 1.11 это не outbound, а конечная
//! точка (`endpoints`): она сама держит пиров и ключи, а правила маршрутов ссылаются
//! на неё по тегу, как на выход. Поля AmneziaWG лежат в корне точки, как секция
//! `[Interface]` у `awg-quick`; без них точка — обычный WireGuard.
//!
//! Значения уже проверены (`wireguard::validate`): сюда они доходят только из модели.

use super::TAG_PROXY;
use crate::wireguard::{AwgKind, WireGuard};
use serde_json::{json, Map, Value};
use std::net::IpAddr;

/// Конечная точка с тегом `proxy`. Пользовательская сеть — userspace-стек
/// (`system: false`): интерфейса в системе нет, права администратора не нужны, а
/// маршруты ведёт наш TUN.
pub(super) fn endpoint(wg: &WireGuard) -> Value {
    let mut e = Map::new();
    e.insert("type".into(), "wireguard".into());
    e.insert("tag".into(), TAG_PROXY.into());
    e.insert("system".into(), false.into());
    e.insert("address".into(), json!(wg.addresses));
    e.insert("private_key".into(), wg.private_key.expose().into());
    if let Some(mtu) = wg.mtu {
        e.insert("mtu".into(), mtu.into());
    }
    let peers: Vec<Value> = wg
        .peers
        .iter()
        .map(|p| {
            let mut peer = Map::new();
            peer.insert("address".into(), p.host.clone().into());
            peer.insert("port".into(), p.port.into());
            peer.insert("public_key".into(), p.public_key.clone().into());
            if let Some(psk) = &p.preshared_key {
                peer.insert("pre_shared_key".into(), psk.expose().into());
            }
            peer.insert("allowed_ips".into(), json!(p.allowed_ips));
            if let Some(k) = &p.keepalive {
                peer.insert("persistent_keepalive_interval".into(), number_or_text(k));
            }
            Value::Object(peer)
        })
        .collect();
    e.insert("peers".into(), peers.into());
    if let Some(awg) = &wg.awg {
        for (name, value) in &awg.params {
            let kind = awg_key_by_json(name).map(|k| k.kind);
            e.insert(name.clone(), awg_value(kind, value));
        }
    }
    Value::Object(e)
}

fn awg_key_by_json(name: &str) -> Option<&'static crate::wireguard::AwgKey> {
    crate::wireguard::AWG_KEYS.iter().find(|k| k.json == name)
}

/// Число остаётся числом (как пишет документация форка), диапазон — строкой.
fn number_or_text(v: &str) -> Value {
    v.parse::<u64>()
        .map_or_else(|_| Value::from(v), Value::from)
}

fn awg_value(kind: Option<AwgKind>, v: &str) -> Value {
    match kind {
        Some(AwgKind::Flag) => Value::Bool(true),
        Some(AwgKind::Count(_) | AwgKind::Range) => number_or_text(v),
        _ => Value::from(v),
    }
}

/// DNS-сервер из `.conf`, если он частный: серверы Amnezia перехватывают порт 53
/// внутри туннеля и отвечают только со своего адреса. Публичные адреса из `.conf`
/// не берём — у KVT свой DoH через туннель.
pub(super) fn private_dns(wg: &WireGuard) -> Option<&str> {
    wg.dns
        .iter()
        .map(String::as_str)
        .find(|d| d.parse::<IpAddr>().is_ok_and(is_private))
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::{Awg, WgPeer};
    use crate::Secret;

    const KEY: &str = "YEocP0XnRPOZ8pZDsCbSDY5vlNwFJCKjR8+Tl5n0DGM=";
    const KEY2: &str = "sRHdS8ss5pR0yWRe7LFSc2iMv5fHgVuOHEv7Hvaw9Qo=";

    fn wg() -> WireGuard {
        WireGuard {
            private_key: Secret::new(KEY),
            addresses: vec!["10.8.0.2/32".into()],
            mtu: Some(1280),
            dns: vec!["1.1.1.1".into(), "10.8.0.1".into()],
            peers: vec![WgPeer {
                public_key: KEY2.into(),
                preshared_key: Some(Secret::new(KEY)),
                host: "203.0.113.5".into(),
                port: 51820,
                allowed_ips: vec!["0.0.0.0/0".into()],
                keepalive: Some("25".into()),
            }],
            awg: None,
        }
    }

    #[test]
    fn plain_wireguard_endpoint() {
        let w = wg();
        let e = endpoint(&w);
        assert_eq!(e["type"], "wireguard");
        assert_eq!(e["tag"], "proxy");
        assert_eq!(e["system"], false);
        assert_eq!(e["mtu"], 1280);
        assert_eq!(e["address"][0], "10.8.0.2/32");
        assert_eq!(e["peers"][0]["address"], "203.0.113.5");
        assert_eq!(e["peers"][0]["port"], 51820);
        assert_eq!(e["peers"][0]["pre_shared_key"], KEY);
        assert_eq!(e["peers"][0]["persistent_keepalive_interval"], 25);
        assert!(e.get("jc").is_none());
    }

    #[test]
    fn awg_fields_keep_their_json_types() {
        let mut w = wg();
        w.peers[0].keepalive = Some("25-35".into());
        w.awg = Some(Awg {
            params: [
                ("jc", "5"),
                ("h1", "1234567890"),
                ("h2", "100-200"),
                ("i1", "<b 0x0102><r 4>"),
                ("random_trailers", "true"),
                ("header_protection_key", KEY),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
            ignored: vec![],
        });
        let e = endpoint(&w);
        assert_eq!(e["jc"], 5);
        assert_eq!(e["h1"], 1_234_567_890);
        assert_eq!(e["h2"], "100-200");
        assert_eq!(e["i1"], "<b 0x0102><r 4>");
        assert_eq!(e["random_trailers"], true);
        assert_eq!(e["header_protection_key"], KEY);
        assert_eq!(e["peers"][0]["persistent_keepalive_interval"], "25-35");
    }

    #[test]
    fn only_private_dns_is_taken() {
        let mut w = wg();
        assert_eq!(private_dns(&w), Some("10.8.0.1"));
        w.dns = vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()];
        assert_eq!(private_dns(&w), None);
        w.dns = vec!["fd00::1".into()];
        assert_eq!(private_dns(&w), Some("fd00::1"));
        w.dns.clear();
        assert_eq!(private_dns(&w), None);
    }
}
