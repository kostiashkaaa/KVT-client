//! Хранилище подписок: `subscriptions.json` в каталоге данных приложения.
//!
//! Ссылка подписки (в ней токен) и тело подписки (в нём UUID и пароли серверов)
//! хранятся зашифрованными DPAPI. Метаданные (название, трафик, срок) — открыто:
//! секретов в них нет, а интерфейсу они нужны без расшифровки.

use crate::dpapi;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kvt_core::parser::CHUNK_SEPARATOR;
use kvt_core::subscription::{next_update_delay, NameFilter, SubscriptionMeta, Validators};
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
    /// Название, которое задал пользователь; важнее названия от провайдера.
    pub custom_title: Option<String>,
    /// Последнее обновление не удалось: когда и почему. Сбрасывается удачным.
    pub last_error: Option<RefreshError>,
    /// Под каким клиентом провайдер отдал серверы (`fetch::PROFILES`): с него
    /// начинается следующее обновление, а не со всей очереди.
    pub agent: Option<String>,
    /// Метки версии сохранённого тела (ETag / Last-Modified) — для ответа 304.
    pub validators: Option<Validators>,
    /// «Расширенные»: фильтр серверов, клиент, ID устройства.
    pub options: SubOptions,
    /// ID устройства, который дал провайдер (вместо своего). Хранится зашифрованным
    /// и в окно не уходит — его можно только заменить.
    pub own_hwid: Option<Secret>,
    /// Провайдер уже просил ID устройства — в режиме «Авто» он уходит сразу.
    pub hwid_asked: bool,
}

/// Настройки подписки из «Расширенных».
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubOptions {
    #[serde(default, skip_serializing_if = "NameFilter::is_empty")]
    pub filter: NameFilter,
    /// Клиент: `None` — очередь (`fetch::Client::Auto`), иначе ключ из
    /// `fetch::PROFILES` или `fetch::CUSTOM` со своим `user_agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "HwidMode::is_auto")]
    pub hwid: HwidMode,
}

impl SubOptions {
    fn is_default(&self) -> bool {
        *self == SubOptions::default()
    }
}

/// Когда отправлять ID устройства.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HwidMode {
    /// Только если провайдер о нём просит.
    #[default]
    Auto,
    /// Всегда — для провайдеров, которые не говорят, а просто не отдают серверы.
    Always,
    Never,
}

impl HwidMode {
    fn is_auto(&self) -> bool {
        *self == HwidMode::Auto
    }
}

/// Что сделать со своим ID устройства при сохранении настроек.
pub enum OwnHwid {
    Keep,
    Set(String),
    Clear,
}

/// Неудачное обновление подписки. Текст — из сообщений загрузчика, без ссылки и
/// токена (см. `fetch::describe`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshError {
    pub at: u64,
    pub message: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSubscription {
    id: String,
    url: Option<String>,
    body: String,
    meta: SubscriptionMeta,
    updated_at: u64,
    next_update: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custom_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<RefreshError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    validators: Option<Validators>,
    #[serde(default, skip_serializing_if = "SubOptions::is_default")]
    options: SubOptions,
    /// Зашифрован DPAPI, как ссылка.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    own_hwid: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    hwid_asked: bool,
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
    /// Записи, которые не расшифровались (файл с другого компьютера или DPAPI
    /// временно недоступен): сохраняются обратно как есть, а не теряются.
    sealed: Vec<StoredSubscription>,
    /// Файл есть, но не прочитался (занят антивирусом, нет доступа). Запись
    /// пустого списка поверх стёрла бы все подписки — сохранять нельзя.
    read_only: bool,
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
            sealed: Vec::new(),
            read_only: false,
        };
        let bytes = match std::fs::read(&store.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return store,
            Err(e) => {
                tracing::warn!(error = %e, "файл подписок не прочитался");
                store.read_only = true;
                return store;
            }
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
            let Ok(body) = unseal(&s.body) else {
                store.sealed.push(s);
                continue;
            };
            let url = match s.url.as_deref().map(unseal) {
                Some(Ok(u)) => Some(Secret::new(u)),
                Some(Err(_)) => {
                    store.sealed.push(s);
                    continue;
                }
                None => None,
            };
            let own_hwid = match s.own_hwid.as_deref().map(unseal) {
                Some(Ok(id)) => Some(Secret::new(id)),
                Some(Err(_)) => {
                    store.sealed.push(s);
                    continue;
                }
                None => None,
            };
            store.subscriptions.push(Subscription {
                id: s.id,
                url,
                body: Secret::new(body),
                meta: s.meta,
                updated_at: s.updated_at,
                next_update: s.next_update,
                custom_title: s.custom_title,
                last_error: s.last_error,
                agent: s.agent,
                validators: s.validators,
                options: s.options,
                own_hwid,
                hwid_asked: s.hwid_asked,
            });
        }
        store.active = file
            .active
            .filter(|id| store.subscriptions.iter().any(|s| &s.id == id))
            .or_else(|| store.subscriptions.first().map(|s| s.id.clone()));
        store
    }

    pub fn save(&self) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::other(kvt_core::i18n::tr(
                "файл подписок не прочитался при запуске — перезапустите KVT, иначе подписки сотрутся",
                "the subscriptions file couldn't be read at startup — restart KVT, otherwise your subscriptions will be erased",
            )));
        }
        let mut subscriptions = self
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
                    custom_title: s.custom_title.clone(),
                    last_error: s.last_error.clone(),
                    agent: s.agent.clone(),
                    validators: s.validators.clone(),
                    options: s.options.clone(),
                    own_hwid: s.own_hwid.as_ref().map(|h| seal(h.expose())).transpose()?,
                    hwid_asked: s.hwid_asked,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        subscriptions.extend(
            self.sealed
                .iter()
                .filter(|s| !self.subscriptions.iter().any(|x| x.id == s.id))
                .cloned(),
        );
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

    /// Каталог данных приложения (там же секрет ID устройства).
    pub fn dir(&self) -> Option<&std::path::Path> {
        self.path.parent()
    }

    pub fn get(&self, id: &str) -> Option<&Subscription> {
        self.subscriptions.iter().find(|s| s.id == id)
    }

    /// Добавляет подписку. Та же ссылка второй раз — обновление существующей,
    /// а не дубликат. Ключи без ссылки собираются в одну группу «Добавлено вручную».
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
        } else if let Some(manual) = self.subscriptions.iter_mut().find(|s| s.url.is_none()) {
            // Каждая вставка — отдельным куском: base64, JSON и ссылки в одном
            // тексте не разобрать. Повторы разбор подписки отбросит сам.
            manual.body = Secret::new(format!(
                "{}\n{CHUNK_SEPARATOR}\n{}",
                manual.body.expose(),
                body
            ));
            manual.updated_at = now;
            return manual.id.clone();
        }
        let id = new_id();
        self.subscriptions.push(Subscription {
            id: id.clone(),
            next_update: next_update(now, meta.update_interval),
            url,
            body: Secret::new(body),
            meta,
            updated_at: now,
            custom_title: None,
            last_error: None,
            agent: None,
            validators: None,
            options: SubOptions::default(),
            own_hwid: None,
            hwid_asked: false,
        });
        self.active = Some(id.clone());
        id
    }

    /// Новое тело подписки. Метки версии сбрасываются: они были у прежнего тела
    /// (новые ставит `set_source`).
    pub fn update(&mut self, id: &str, body: String, meta: SubscriptionMeta, now: u64) {
        if let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == id) {
            s.next_update = next_update(now, meta.update_interval);
            s.body = Secret::new(body);
            s.meta = meta;
            s.updated_at = now;
            s.last_error = None;
            s.validators = None;
        }
    }

    /// Каким клиентом пришло тело и его метки версии; `hwid_sent` — серверы
    /// отдали в ответ на ID устройства (провайдер его ждёт).
    pub fn set_source(
        &mut self,
        id: &str,
        agent: &str,
        validators: Option<Validators>,
        hwid_sent: bool,
    ) {
        if let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == id) {
            s.agent = Some(agent.to_owned());
            s.validators = validators;
            s.hwid_asked |= hwid_sent;
        }
    }

    /// Новые «Расширенные». Возвращает `None`, если подписки нет, иначе — меняется
    /// ли запрос к провайдеру (клиент или ID устройства): тогда запомненный
    /// клиент и метки версии больше не годятся, подписку надо загрузить заново.
    pub fn set_options(&mut self, id: &str, options: SubOptions, own: OwnHwid) -> Option<bool> {
        let s = self.subscriptions.iter_mut().find(|s| s.id == id)?;
        let old_hwid = s.own_hwid.as_ref().map(|h| h.expose().to_owned());
        match own {
            OwnHwid::Keep => {}
            OwnHwid::Set(h) => s.own_hwid = Some(Secret::new(h)),
            OwnHwid::Clear => s.own_hwid = None,
        }
        let request_changed = s.options.client != options.client
            || s.options.user_agent != options.user_agent
            || s.options.hwid != options.hwid
            || s.own_hwid.as_ref().map(|h| h.expose().to_owned()) != old_hwid;
        if request_changed {
            s.agent = None;
            s.validators = None;
        }
        s.options = options;
        Some(request_changed)
    }

    /// Сервер ответил «не изменилась» (304): тело прежнее, обновлены только
    /// пришедшие метаданные и расписание.
    pub fn not_modified(&mut self, id: &str, fresh: SubscriptionMeta, now: u64) {
        if let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == id) {
            s.meta.refresh_from(fresh);
            s.next_update = next_update(now, s.meta.update_interval);
            s.updated_at = now;
            s.last_error = None;
        }
    }

    /// Неудачное обновление: повторим позже, но не раньше чем через час.
    /// `error` — причина для карточки подписки (без ссылки и токена).
    pub fn postpone(&mut self, id: &str, now: u64, error: Option<&str>) {
        if let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == id) {
            s.next_update = next_update(now, Duration::from_secs(3600));
            if let Some(message) = error {
                s.last_error = Some(RefreshError {
                    at: now,
                    message: message.chars().take(300).collect(),
                });
            }
        }
    }

    /// Своё название подписки; пустое — снова название от провайдера.
    pub fn rename(&mut self, id: &str, title: &str) -> bool {
        let title = title.trim();
        let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == id) else {
            return false;
        };
        s.custom_title = Some(title.to_owned()).filter(|t| !t.is_empty());
        true
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
    fn undecryptable_entries_survive_save() {
        let path = tmp("sealed");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let raw = serde_json::json!({
            "version": FILE_VERSION,
            "active": null,
            "subscriptions": [{
                "id": "foreign",
                "url": null,
                "body": "bm90LWRwYXBp",
                "meta": SubscriptionMeta::default(),
                "updated_at": 1,
                "next_update": 2
            }]
        });
        std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        let store = Store::load(path.clone());
        assert!(store.subscriptions.is_empty());
        store.save().unwrap();
        let back: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(back["subscriptions"][0]["id"], "foreign");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
        let s = loaded.get(&id).unwrap();
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
        assert_eq!(store.get(&a).unwrap().body.expose(), "new");
    }

    #[test]
    fn manual_keys_share_one_group() {
        let mut store = Store::load(tmp("manual"));
        let a = store.add(None, "vless://a".into(), SubscriptionMeta::default(), 1);
        let b = store.add(None, "vless://b".into(), SubscriptionMeta::default(), 2);
        assert_eq!(a, b);
        assert_eq!(store.subscriptions.len(), 1);
        assert_eq!(
            store.get(&a).unwrap().body.expose(),
            format!("vless://a\n{CHUNK_SEPARATOR}\nvless://b")
        );
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
    fn rename_and_refresh_error_survive_reload() {
        let path = tmp("rename");
        let mut store = Store::load(path.clone());
        let id = store.add(
            Some(Secret::new(URL)),
            BODY.into(),
            SubscriptionMeta::default(),
            1,
        );
        assert!(store.rename(&id, "  Рабочая  "));
        store.postpone(&id, 5, Some("Сервер подписки ответил ошибкой 403"));
        store.save().unwrap();

        let mut loaded = Store::load(path.clone());
        let s = loaded.get(&id).unwrap();
        assert_eq!(s.custom_title.as_deref(), Some("Рабочая"));
        assert_eq!(s.last_error.as_ref().map(|e| e.at), Some(5));
        // Удачное обновление стирает ошибку, но не своё название.
        loaded.update(&id, BODY.into(), SubscriptionMeta::default(), 9);
        let s = loaded.get(&id).unwrap();
        assert!(s.last_error.is_none());
        assert_eq!(s.custom_title.as_deref(), Some("Рабочая"));
        // Пустое название — снова от провайдера.
        assert!(loaded.rename(&id, " "));
        assert!(loaded.get(&id).unwrap().custom_title.is_none());
        assert!(!loaded.rename("нет такой", "x"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn source_survives_reload_and_new_body_drops_validators() {
        let path = tmp("source");
        let mut store = Store::load(path.clone());
        let id = store.add(
            Some(Secret::new(URL)),
            BODY.into(),
            SubscriptionMeta::default(),
            1,
        );
        let validators = Validators {
            etag: Some("\"v1\"".into()),
            last_modified: None,
        };
        store.set_source(&id, "happ", Some(validators.clone()), false);
        store.postpone(&id, 2, Some("ошибка"));
        store.save().unwrap();

        let mut loaded = Store::load(path.clone());
        let s = loaded.get(&id).unwrap();
        assert_eq!(s.agent.as_deref(), Some("happ"));
        assert_eq!(s.validators.as_ref(), Some(&validators));
        // 304: тело и метки прежние, ошибка стёрта, время обновления новое.
        loaded.not_modified(&id, SubscriptionMeta::default(), 50);
        let s = loaded.get(&id).unwrap();
        assert_eq!(s.body.expose(), BODY);
        assert_eq!(s.updated_at, 50);
        assert!(s.last_error.is_none());
        assert!(s.validators.is_some());
        // Новое тело — меток прежнего уже нет, клиент остаётся.
        loaded.update(&id, BODY.into(), SubscriptionMeta::default(), 60);
        let s = loaded.get(&id).unwrap();
        assert!(s.validators.is_none());
        assert_eq!(s.agent.as_deref(), Some("happ"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn old_file_without_new_fields_loads() {
        let path = tmp("old");
        let mut store = Store::load(path.clone());
        store.add(None, BODY.into(), SubscriptionMeta::default(), 1);
        store.save().unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("custom_title") && !raw.contains("last_error"));
        assert!(!raw.contains("agent") && !raw.contains("validators"));
        assert!(!raw.contains("options") && !raw.contains("hwid"));
        assert_eq!(Store::load(path.clone()).subscriptions.len(), 1);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn options_and_own_hwid_survive_reload_without_plaintext() {
        let path = tmp("options");
        let mut store = Store::load(path.clone());
        let id = store.add(
            Some(Secret::new(URL)),
            BODY.into(),
            SubscriptionMeta::default(),
            1,
        );
        store.set_source(&id, "happ", Some(Validators::default()), true);
        let options = SubOptions {
            filter: NameFilter::parse("nl", "").unwrap(),
            client: Some("incy".into()),
            user_agent: None,
            hwid: HwidMode::Always,
        };
        let own = OwnHwid::Set("PROVIDER-HWID-123".into());
        // Клиент и ID сменились — запомненный клиент и метки сброшены.
        assert_eq!(store.set_options(&id, options.clone(), own), Some(true));
        assert!(store.get(&id).unwrap().agent.is_none());
        assert_eq!(
            store.set_options("нет такой", SubOptions::default(), OwnHwid::Keep),
            None
        );
        store.save().unwrap();
        assert!(!std::fs::read_to_string(&path)
            .unwrap()
            .contains("PROVIDER-HWID"));

        let mut loaded = Store::load(path.clone());
        let s = loaded.get(&id).unwrap();
        assert_eq!(s.options, options);
        assert!(s.hwid_asked);
        assert_eq!(
            s.own_hwid.as_ref().map(Secret::expose),
            Some("PROVIDER-HWID-123")
        );
        // Только фильтр — запрос прежний.
        let only_filter = SubOptions {
            filter: NameFilter::default(),
            ..options
        };
        assert_eq!(
            loaded.set_options(&id, only_filter, OwnHwid::Keep),
            Some(false)
        );
        assert_eq!(
            loaded.set_options(&id, SubOptions::default(), OwnHwid::Clear),
            Some(true)
        );
        assert!(loaded.get(&id).unwrap().own_hwid.is_none());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
