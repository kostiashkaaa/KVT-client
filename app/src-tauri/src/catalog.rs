//! Единый список серверов: все подписки и вручную добавленные ключи, группами.
//!
//! Сервер выбирается по постоянному ключу, а не по номеру в списке: провайдер
//! может обновить подписку и поменять порядок, а выбор и итоги проверок должны
//! остаться за тем же сервером. В ключ не входят секреты (UUID, пароли).

use crate::store::{Store, Subscription};
use crate::{ServerSummary, SubscriptionInfo};
use kvt_core::parser::parse_subscription_body;
use kvt_core::Server;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Подписка, из которой сервер.
    pub sub: String,
    pub key: String,
    pub server: Server,
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

/// Ключ: подписка + протокол, адрес, порт, транспорт и параметры TLS.
pub(crate) fn key(sub: &str, s: &Server) -> String {
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
    h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Название подписки: от провайдера, иначе хост ссылки (токен — в пути, хост не секрет).
pub(crate) fn title(s: &Subscription) -> String {
    s.meta.title.clone().unwrap_or_else(|| {
        s.url
            .as_ref()
            .and_then(|u| url::Url::parse(u.expose()).ok())
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "Добавлено вручную".into())
    })
}

/// Ключи для серверов одной подписки; одинаковые получают суффикс.
fn keys(sub: &str, servers: &[Server], taken: &mut HashSet<String>) -> Vec<String> {
    servers
        .iter()
        .map(|s| {
            let base = key(sub, s);
            let mut k = base.clone();
            let mut n = 2;
            while !taken.insert(k.clone()) {
                k = format!("{base}-{n}");
                n += 1;
            }
            k
        })
        .collect()
}

pub(crate) fn build(store: &Store) -> (Vec<Group>, Vec<Entry>) {
    let mut groups = Vec::new();
    let mut entries = Vec::new();
    let mut taken = HashSet::new();
    for sub in &store.subscriptions {
        let content = parse_subscription_body(sub.body.expose());
        let keys = keys(&sub.id, &content.servers, &mut taken);
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
                .map(|(s, k)| ServerSummary::new(s, k))
                .collect(),
            info: content.info,
            errors: content.errors.len(),
        });
        entries.extend(
            content
                .servers
                .into_iter()
                .zip(keys)
                .map(|(server, key)| Entry {
                    sub: sub.id.clone(),
                    key,
                    server,
                }),
        );
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
