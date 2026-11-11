//! Единый список серверов: все подписки и вручную добавленные ключи, группами.
//!
//! Сервер выбирается по постоянному ключу, а не по номеру в списке: провайдер
//! может обновить подписку и поменять порядок, а выбор и итоги проверок должны
//! остаться за тем же сервером. В ключ не входят секреты (UUID, пароли).

use crate::store::{Store, Subscription};
use crate::{ServerSummary, SubscriptionInfo};
use kvt_core::model::Transport;
use kvt_core::parser::parse_subscription_body;
use kvt_core::Server;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Подписка, из которой сервер.
    pub sub: String,
    pub key: String,
    pub server: Server,
    /// Тот же выход, что у сервера с этим ключом (выше в списке): совпадает всё,
    /// кроме названия — провайдер повторил сервер под другим флагом. Отдельным
    /// кандидатом автопереключения такой сервер не считается.
    pub same_as: Option<String>,
}

impl Entry {
    /// Ключ «настоящего» сервера: у повтора — ключ первого такого же.
    pub fn exit_key(&self) -> &str {
        self.same_as.as_deref().unwrap_or(&self.key)
    }
}

/// Отпечаток выхода: сервер целиком, кроме названия. В нём ключи и пароли, поэтому
/// наружу он не уходит — только сравнивается.
fn exit_id(s: &Server) -> [u8; 32] {
    let mut unnamed = s.clone();
    unnamed.name.clear();
    Sha256::digest(serde_json::to_vec(&unnamed).unwrap_or_default()).into()
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Group {
    pub id: String,
    pub title: String,
    pub by_url: bool,
    pub updated_at: u64,
    pub meta: SubscriptionInfo,
    pub servers: Vec<ServerSummary>,
    /// Служебные строки провайдера (например, «Трафик: …»).
    pub info: Vec<String>,
    /// Сколько строк подписки не разобралось.
    pub errors: usize,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Вид транспорта без параметров (путь, хост, имя сервиса).
pub(crate) fn transport_kind(t: &Transport) -> &'static str {
    match t {
        Transport::Tcp => "tcp",
        Transport::Ws { .. } => "ws",
        Transport::Grpc { .. } => "grpc",
        Transport::HttpUpgrade { .. } => "httpupgrade",
        Transport::Xhttp { .. } => "xhttp",
        Transport::Quic => "quic",
    }
}

/// Основа ключа: подписка + протокол, адрес, порт и вид транспорта. Параметры TLS и
/// Reality (SNI, отпечаток, short_id, ключ) провайдеры меняют, а сервер остаётся
/// тем же — выбор и подключение не должны из-за этого теряться.
fn base_key(sub: &str, s: &Server) -> String {
    let mut h = Sha256::new();
    h.update(b"kvt-server-v2\0");
    h.update(sub.as_bytes());
    h.update(b"\0");
    h.update(s.protocol.kind().as_bytes());
    h.update(b"\0");
    h.update(s.address.to_ascii_lowercase().as_bytes());
    h.update(s.port.to_be_bytes());
    h.update(transport_kind(&s.transport).as_bytes());
    hex(&h.finalize()[..8])
}

/// Различие вариантов одной точки (тот же адрес и порт, но другой SNI или путь).
fn variant(s: &Server) -> String {
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&s.transport).unwrap_or_default());
    h.update(serde_json::to_vec(&s.security).unwrap_or_default());
    hex(&h.finalize()[..4])
}

/// Ключ до 0.9.2 (с параметрами TLS) — только для переноса сохранённого выбора.
fn legacy_key(sub: &str, s: &Server) -> String {
    let mut h = Sha256::new();
    h.update(b"kvt-server-v1\0");
    h.update(sub.as_bytes());
    h.update(b"\0");
    h.update(s.protocol.kind().as_bytes());
    h.update(b"\0");
    h.update(s.address.to_ascii_lowercase().as_bytes());
    h.update(s.port.to_be_bytes());
    h.update(serde_json::to_vec(&s.transport).unwrap_or_default());
    h.update(serde_json::to_vec(&s.security).unwrap_or_default());
    hex(&h.finalize()[..8])
}

/// Название подписки: своё, иначе от провайдера, иначе хост ссылки (токен — в пути,
/// хост не секрет).
pub(crate) fn title(s: &Subscription) -> String {
    s.custom_title
        .clone()
        .or_else(|| s.meta.title.clone())
        .unwrap_or_else(|| {
            s.url
                .as_ref()
                .and_then(|u| url::Url::parse(u.expose()).ok())
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_else(|| "Добавлено вручную".into())
        })
}

/// Ключи для серверов одной подписки. Если у нескольких серверов одна основа
/// (варианты одной точки), к ней добавляется различие параметров; совсем
/// одинаковые получают номер.
fn keys(sub: &str, servers: &[Server], taken: &mut HashSet<String>) -> Vec<String> {
    let bases: Vec<String> = servers.iter().map(|s| base_key(sub, s)).collect();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for b in &bases {
        *counts.entry(b.as_str()).or_default() += 1;
    }
    servers
        .iter()
        .zip(&bases)
        .map(|(s, base)| {
            let base = if counts[base.as_str()] > 1 {
                format!("{base}-{}", variant(s))
            } else {
                base.clone()
            };
            unique(base, taken)
        })
        .collect()
}

fn unique(base: String, taken: &mut HashSet<String>) -> String {
    let mut k = base.clone();
    let mut n = 2;
    while !taken.insert(k.clone()) {
        k = format!("{base}-{n}");
        n += 1;
    }
    k
}

/// Прежние ключи (до 0.9.2) → нынешние, чтобы выбранный сервер и «Недавние» в трее
/// пережили обновление KVT. Прежние считаются так же, как считались: с номером у
/// одинаковых по всему списку.
pub(crate) fn legacy_keys(store: &Store, entries: &[Entry]) -> HashMap<String, String> {
    let mut taken = HashSet::new();
    let mut map = HashMap::new();
    for sub in &store.subscriptions {
        let current = entries.iter().filter(|e| e.sub == sub.id);
        for (server, entry) in parse_subscription_body(sub.body.expose())
            .servers
            .iter()
            .zip(current)
        {
            let old = unique(legacy_key(&sub.id, server), &mut taken);
            map.insert(old, entry.key.clone());
        }
    }
    map
}

pub(crate) fn build(store: &Store) -> (Vec<Group>, Vec<Entry>) {
    let mut groups = Vec::new();
    let mut entries = Vec::new();
    let mut taken = HashSet::new();
    // Первый сервер с таким выходом — во всех подписках сразу.
    let mut exits: HashMap<[u8; 32], String> = HashMap::new();
    for sub in &store.subscriptions {
        let content = parse_subscription_body(sub.body.expose());
        let keys = keys(&sub.id, &content.servers, &mut taken);
        let same_as: Vec<Option<String>> = content
            .servers
            .iter()
            .zip(&keys)
            .map(|(s, k)| {
                let first = exits.entry(exit_id(s)).or_insert_with(|| k.clone());
                (first != k).then(|| first.clone())
            })
            .collect();
        groups.push(Group {
            id: sub.id.clone(),
            title: title(sub),
            by_url: sub.url.is_some(),
            updated_at: sub.updated_at,
            meta: SubscriptionInfo::from(&sub.meta),
            servers: content
                .servers
                .iter()
                .zip(&keys)
                .zip(&same_as)
                .map(|((s, k), same)| ServerSummary::new(s, k).same_as(same.clone()))
                .collect(),
            info: content.info,
            errors: content.errors.len(),
        });
        entries.extend(content.servers.into_iter().zip(keys).zip(same_as).map(
            |((server, key), same_as)| Entry {
                sub: sub.id.clone(),
                key,
                server,
                same_as,
            },
        ));
    }
    (groups, entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::parser::{parse_uri, Entry as Parsed};

    fn server(uri: &str) -> Server {
        match parse_uri(uri).unwrap() {
            Parsed::Server(s) => *s,
            Parsed::Info(_) => panic!("ожидался сервер"),
        }
    }

    const A: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?security=reality&sni=a.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw#A";

    fn key(sub: &str, s: &Server) -> String {
        keys(sub, std::slice::from_ref(s), &mut HashSet::new()).remove(0)
    }

    #[test]
    fn key_ignores_name_order_and_secrets() {
        let a = server(A);
        let mut renamed = a.clone();
        renamed.name = "🇳🇱 другое имя".into();
        assert_eq!(key("s1", &a), key("s1", &renamed));
        // Другой UUID того же сервера — тот же ключ: секрет в ключ не входит.
        let other_user = server(&A.replace("b831381d", "c831381d"));
        assert_eq!(key("s1", &a), key("s1", &other_user));
        assert!(!key("s1", &a).contains("b831381d"));
        // Та же точка в другой подписке — другой сервер.
        assert_ne!(key("s1", &a), key("s2", &a));
        let mut other_port = a.clone();
        other_port.port = 8443;
        assert_ne!(key("s1", &a), key("s1", &other_port));
    }

    /// Провайдер сменил SNI и отпечаток Reality — сервер тот же, выбор не теряется.
    #[test]
    fn key_survives_tls_parameter_change() {
        let a = server(A);
        let b = server(&A.replace("sni=a.com", "sni=b.com&fp=qq"));
        assert_ne!(a.security, b.security);
        assert_eq!(key("s1", &a), key("s1", &b));
    }

    /// Два варианта одной точки (разные SNI) различаются, и ключ каждого не
    /// зависит от порядка в подписке.
    #[test]
    fn variants_of_one_endpoint_are_distinct_and_stable() {
        let a = server(A);
        let b = server(&A.replace("sni=a.com", "sni=b.com"));
        let ab = keys("s", &[a.clone(), b.clone()], &mut HashSet::new());
        let ba = keys("s", &[b, a], &mut HashSet::new());
        assert_ne!(ab[0], ab[1]);
        assert_eq!(ab[0], ba[1]);
        assert_eq!(ab[1], ba[0]);
    }

    #[test]
    fn legacy_keys_map_to_current() {
        let mut store = Store::load(std::env::temp_dir().join("kvt-catalog-legacy-none.json"));
        store.subscriptions.clear();
        let id = store.add(None, A.into(), Default::default(), 0);
        let (_, entries) = build(&store);
        let map = legacy_keys(&store, &entries);
        let old = legacy_key(&id, &server(A));
        assert_eq!(map.get(&old), Some(&entries[0].key));
    }

    #[test]
    fn same_exit_under_other_flag_is_marked() {
        let mut store = Store::load(std::env::temp_dir().join("kvt-catalog-same-none.json"));
        store.subscriptions.clear();
        let other_flag = A.replace("#A", "#%F0%9F%87%A9%F0%9F%87%AA%20DE");
        let other_user = A.replace("b831381d", "c831381d");
        let body = format!(
            "{A}
{other_flag}
{other_user}"
        );
        store.add(None, body, Default::default(), 0);
        let (_, entries) = build(&store);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].same_as, None);
        // Тот же адрес, порт и UUID, другое название — тот же выход.
        assert_eq!(entries[1].same_as.as_deref(), Some(entries[0].key.as_str()));
        assert_eq!(entries[1].exit_key(), entries[0].key);
        // Другой UUID — другой пользователь, отдельный сервер.
        assert_eq!(entries[2].same_as, None);
    }

    #[test]
    fn duplicates_get_distinct_keys() {
        let a = server(A);
        let mut taken = HashSet::new();
        let ks = keys("s", &[a.clone(), a], &mut taken);
        assert_eq!(ks.len(), 2);
        assert_ne!(ks[0], ks[1]);
        assert!(ks[1].ends_with("-2"));
    }
}
