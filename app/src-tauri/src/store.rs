//! Хранилище подписок: `subscriptions.json` в каталоге данных приложения.
//!
//! Ссылка подписки (в ней токен) и тело подписки (в нём UUID и пароли серверов)
//! хранятся зашифрованными DPAPI. Метаданные (название, трафик, срок) — открыто:
//! секретов в них нет, а интерфейсу они нужны без расшифровки.

use crate::dpapi;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kvt_core::subscription::{next_update_delay, SubscriptionMeta};
use kvt_core::Secret;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

const FILE_VERSION: u32 = 1;

#[derive(Clone)]
pub struct Subscription {
    pub id: String,
    /// `None` — подписка вставлена вручную (ссылки на серверы), обновлять нечего.
    pub url: Option<Secret>,
    pub body: Secret,
    pub meta: SubscriptionMeta,
    pub updated_at: u64,
    /// Unix-время следующего автообновления (с разбросом, чтобы не ходить синхронно).
    pub next_update: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredSubscription {
    id: String,
    url: Option<String>,
    body: String,
    meta: SubscriptionMeta,
    updated_at: u64,
    next_update: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct StoreFile {
    version: u32,
    active: Option<String>,
    subscriptions: Vec<StoredSubscription>,
}

pub struct Store {
    path: PathBuf,
    pub subscriptions: Vec<Subscription>,
    pub active: Option<String>,
}

fn seal(plain: &str) -> io::Result<String> {
    Ok(STANDARD.encode(dpapi::protect(plain.as_bytes())?))
}

fn unseal(sealed: &str) -> io::Result<String> {
    let bytes = STANDARD
        .decode(sealed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    String::from_utf8(dpapi::unprotect(&bytes)?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn new_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", nanos ^ u128::from(std::process::id()))
}

/// Число из [0, 1) для разброса времени обновления.
fn jitter_unit() -> f64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    f64::from(nanos % 1_000_000) / 1_000_000.0
}

fn next_update(now: u64, interval: Duration) -> u64 {
    now + next_update_delay(interval, jitter_unit()).as_secs()
}

impl Store {
    /// Загружает хранилище. Повреждённый файл не роняет приложение: он
    /// сохраняется рядом как `.broken`, а работа начинается с пустого списка.
    pub fn load(path: PathBuf) -> Self {
        let mut store = Store {
            path,
            subscriptions: Vec::new(),
            active: None,
        };
        let Ok(bytes) = std::fs::read(&store.path) else {
            return store;
        };
        let file: StoreFile = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(_) => {
                let _ = std::fs::rename(&store.path, store.path.with_extension("json.broken"));
                return store;
            }
        };
        for s in file.subscriptions {
            // Подписку, которую нельзя расшифровать (например, файл с другого
            // компьютера), просто пропускаем.
            let Ok(body) = unseal(&s.body) else { continue };
            let url = match s.url.as_deref().map(unseal) {
                Some(Ok(u)) => Some(Secret::new(u)),
                Some(Err(_)) => continue,
                None => None,
            };
            store.subscriptions.push(Subscription {
                id: s.id,
                url,
                body: Secret::new(body),
                meta: s.meta,
                updated_at: s.updated_at,
                next_update: s.next_update,
            });
        }
        store.active = file
            .active
            .filter(|id| store.subscriptions.iter().any(|s| &s.id == id))
            .or_else(|| store.subscriptions.first().map(|s| s.id.clone()));
        store
    }

    pub fn save(&self) -> io::Result<()> {
        let subscriptions = self
            .subscriptions
            .iter()
            .map(|s| {
                Ok(StoredSubscription {
                    id: s.id.clone(),
                    url: s.url.as_ref().map(|u| seal(u.expose())).transpose()?,
                    body: seal(s.body.expose())?,
                    meta: s.meta.clone(),
                    updated_at: s.updated_at,
                    next_update: s.next_update,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let file = StoreFile {
            version: FILE_VERSION,
            active: self.active.clone(),
            subscriptions,
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, &self.path)
    }

    pub fn active(&self) -> Option<&Subscription> {
        let id = self.active.as_ref()?;
        self.subscriptions.iter().find(|s| &s.id == id)
    }

    pub fn get(&self, id: &str) -> Option<&Subscription> {
        self.subscriptions.iter().find(|s| s.id == id)
    }

    pub fn set_active(&mut self, id: &str) -> bool {
        let exists = self.subscriptions.iter().any(|s| s.id == id);
        if exists {
            self.active = Some(id.to_owned());
        }
        exists
    }

    /// Добавляет подписку и делает её активной. Та же ссылка второй раз —
    /// обновление существующей подписки, а не дубликат.
    pub fn add(
        &mut self,
        url: Option<Secret>,
        body: String,
        meta: SubscriptionMeta,
        now: u64,
    ) -> String {
        if let Some(u) = &url {
            if let Some(id) = self
                .subscriptions
                .iter()
                .find(|s| s.url.as_ref().map(Secret::expose) == Some(u.expose()))
                .map(|s| s.id.clone())
            {
                self.update(&id, body, meta, now);
                self.active = Some(id.clone());
                return id;
            }
        }
        let id = new_id();
        self.subscriptions.push(Subscription {
            id: id.clone(),
            next_update: next_update(now, meta.update_interval),
            url,
            body: Secret::new(body),
            meta,
            updated_at: now,
        });
        self.active = Some(id.clone());
        id
    }

    pub fn update(&mut self, id: &str, body: String, meta: SubscriptionMeta, now: u64) {
        if let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == id) {
            s.next_update = next_update(now, meta.update_interval);
            s.body = Secret::new(body);
            s.meta = meta;
            s.updated_at = now;
        }
    }

    /// Неудачное обновление: повторим позже, но не раньше чем через час.
    pub fn postpone(&mut self, id: &str, now: u64) {
        if let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == id) {
            s.next_update = next_update(now, Duration::from_secs(3600));
        }
    }

    pub fn remove(&mut self, id: &str) {
        self.subscriptions.retain(|s| s.id != id);
        if self.active.as_deref() == Some(id) {
            self.active = self.subscriptions.first().map(|s| s.id.clone());
        }
    }

    /// Подписки по ссылке, которым пора обновиться.
    pub fn due(&self, now: u64) -> Vec<(String, Secret)> {
        self.subscriptions
            .iter()
            .filter(|s| now >= s.next_update)
            .filter_map(|s| s.url.clone().map(|u| (s.id.clone(), u)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?security=reality&sni=a.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw#NL";
    const URL: &str = "https://sub.example.com/SECRET-TOKEN";

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kvt-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("subscriptions.json")
    }

    #[test]
    fn roundtrip_without_plaintext_secrets_on_disk() {
        let path = tmp("roundtrip");
        let mut store = Store::load(path.clone());
        let id = store.add(
            Some(Secret::new(URL)),
            BODY.into(),
            SubscriptionMeta::default(),
            1_000,
        );
        store.save().unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("SECRET-TOKEN"));
        assert!(!raw.contains("b831381d"));

        let loaded = Store::load(path.clone());
        assert_eq!(loaded.active.as_deref(), Some(id.as_str()));
        let s = loaded.active().unwrap();
        assert_eq!(s.url.as_ref().unwrap().expose(), URL);
        assert_eq!(s.body.expose(), BODY);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn same_url_updates_instead_of_duplicating() {
        let mut store = Store::load(tmp("dedup"));
        let a = store.add(
            Some(Secret::new(URL)),
            "old".into(),
            SubscriptionMeta::default(),
            1,
        );
        let b = store.add(
            Some(Secret::new(URL)),
            "new".into(),
            SubscriptionMeta::default(),
            2,
        );
        assert_eq!(a, b);
        assert_eq!(store.subscriptions.len(), 1);
        assert_eq!(store.active().unwrap().body.expose(), "new");
    }

    #[test]
    fn schedule_and_remove() {
        let mut store = Store::load(tmp("due"));
        let manual = store.add(None, BODY.into(), SubscriptionMeta::default(), 0);
        let by_url = store.add(
            Some(Secret::new(URL)),
            BODY.into(),
            SubscriptionMeta::default(),
            0,
        );
        // Интервал по умолчанию 12 ч ± 15 %: сразу обновлять нечего, через сутки — только подписку по ссылке.
        assert!(store.due(3600).is_empty());
        let due = store.due(24 * 3600);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0, by_url);
        store.remove(&by_url);
        assert_eq!(store.active.as_deref(), Some(manual.as_str()));
    }

    #[test]
    fn corrupt_file_is_set_aside() {
        let path = tmp("corrupt");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ broken").unwrap();
        let store = Store::load(path.clone());
        assert!(store.subscriptions.is_empty());
        assert!(path.with_extension("json.broken").exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
