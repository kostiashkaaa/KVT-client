//! Подписки: добавление, удаление, ручное и фоновое обновление.

use crate::store::{HwidMode, OwnHwid, Store, SubOptions, Subscription};
use crate::{catalog, disconnect_service, display_name, fetch, query_status, watchdog, AppState};
use kvt_core::ipc::ServiceStatus;
use kvt_core::parser::{normalize_pasted, parse_subscription_body};
use kvt_core::subscription::{
    header_value, split_input, NameFilter, SubscriptionMeta, Validators, MAX_BODY_BYTES,
};
use kvt_core::Secret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

mod edit;
mod error;
mod options;
mod refresh;
mod selection;
mod view;

// Команды окна (`generate_handler!` в main.rs) и то, что зовут трей и перенос,
// доступны как `subs::…`, как до разбиения на модули.
pub use edit::*;
pub use error::SubsError;
pub use options::*;
pub use refresh::*;
use selection::*;
pub use view::*;

/// Событие для интерфейса: подписки или их серверы изменились.
pub const CHANGED_EVENT: &str = "subscriptions-changed";
const STORE_FILE: &str = "subscriptions.json";
/// Сколько ждать своей очереди к серверу подписки, когда несколько подписок одного
/// провайдера загружаются подряд (NetGovernor: не больше двух запросов в минуту).
const BATCH_WAIT: Duration = Duration::from_secs(65);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lock_err<T>(_: T) -> SubsError {
    SubsError::State
}

pub fn load(app: &AppHandle) -> Result<Store, SubsError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| SubsError::DataDir(e.to_string()))?;
    Ok(Store::load(dir.join(STORE_FILE)))
}

/// Пересобирает единый список серверов и группы для интерфейса.
pub fn rebuild(state: &AppState) -> Result<(), SubsError> {
    let (groups, entries) = {
        let store = state.store.lock().map_err(lock_err)?;
        store.as_ref().map(catalog::build).unwrap_or_default()
    };
    // Итоги проверок привязаны к ключам: у исчезнувших серверов они не нужны.
    state
        .outcomes
        .lock()
        .map_err(lock_err)?
        .retain(|key, _| entries.iter().any(|e| &e.key == key));
    state
        .outcome_times
        .lock()
        .map_err(lock_err)?
        .retain(|key, _| entries.iter().any(|e| &e.key == key));
    // Адреса и пароли серверов не должны попасть в журналы и экспорт диагностики.
    kvt_core::redact::set_servers(entries.iter().flat_map(|e| e.server.endpoints()));
    kvt_core::redact::set_secrets(entries.iter().flat_map(|e| e.server.secrets()));
    *state.servers.lock().map_err(lock_err)? = entries;
    *state.groups.lock().map_err(lock_err)? = groups;
    Ok(())
}

/// Что добавилось: интерфейс сразу выбирает первый сервер новой подписки.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Added {
    group: String,
    first: Option<String>,
    servers: usize,
}

/// `body` — что добавили: выбираем первый сервер из него, а не из всей группы
/// (ручные ключи дописываются в общую группу).
fn added(state: &AppState, id: String, body: &str) -> Result<Added, SubsError> {
    rebuild(state)?;
    let new = parse_subscription_body(body).servers;
    let servers = state.servers.lock().map_err(lock_err)?;
    let first = new
        .first()
        .and_then(|s| servers.iter().find(|e| e.sub == id && e.server == *s))
        .or_else(|| servers.iter().find(|e| e.sub == id))
        .map(|e| e.key.clone());
    Ok(Added {
        group: id,
        first,
        servers: new.len(),
    })
}

fn with_store<R>(state: &AppState, f: impl FnOnce(&mut Store) -> R) -> Result<R, SubsError> {
    let mut guard = state.store.lock().map_err(lock_err)?;
    let store = guard.as_mut().ok_or(SubsError::NotLoaded)?;
    let result = f(store);
    store.save().map_err(|e| {
        SubsError::Save(crate::errors::io(
            kvt_core::i18n::tr(
                "Не удалось сохранить подписки",
                "Couldn't save subscriptions",
            ),
            &e,
        ))
    })?;
    Ok(result)
}

fn ensure_servers(body: &str) -> Result<(), SubsError> {
    if parse_subscription_body(body).servers.is_empty() {
        return Err(SubsError::NoServers);
    }
    Ok(())
}

fn notify(app: &AppHandle) {
    let _ = app.emit(CHANGED_EVENT, ());
}

/// Ключи, вставленные вручную (ссылки на серверы, base64 или конфиги), — в группу
/// «Добавлено вручную».
fn add_pasted(state: &AppState, body: &str) -> Result<Added, SubsError> {
    // В ручной группе — только ссылки: base64 раскрыт, конфиги Xray и sing-box переведены.
    let body = normalize_pasted(body);
    ensure_servers(&body)?;
    let id = with_store(state, |s| {
        s.add(None, body.clone(), SubscriptionMeta::default(), now())
    })?;
    added(state, id, &body)
}

/// Подписка по ссылке. Та же ссылка второй раз — обновление прежней подписки.
async fn add_url(state: &AppState, raw: &str, patient: bool) -> Result<Added, SubsError> {
    let url = fetch::validate_url(raw)?;
    let host = url.host_str().unwrap_or_default();
    if patient {
        fetch::acquire_patiently(&state.governor, host, BATCH_WAIT).await?;
    } else {
        fetch::acquire(&state.governor, host)?;
    }
    // Та же ссылка второй раз — с настройками прежней подписки.
    let plan = Plan::of(state, |s| {
        s.url.as_ref().map(Secret::expose) == Some(url.as_str())
    })?;
    let fetched = fetch::fetch(&url, &plan.hints(host, None)?.hints(&state.governor)).await?;
    ensure_servers(&fetched.body)?;
    let body = fetched.body.clone();
    let id = with_store(state, |s| {
        let id = s.add(
            Some(Secret::new(url.as_str())),
            fetched.body,
            fetched.meta,
            now(),
        );
        s.set_source(&id, fetched.agent, fetched.validators, fetched.hwid_sent);
        id
    })?;
    added(state, id, &body)
}

/// Итог добавления вставки: что добавилось и что нет.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddReport {
    /// Первая добавленная группа и её первый сервер — интерфейс выберет его.
    group: Option<String>,
    first: Option<String>,
    servers: usize,
    /// Сколько подписок по ссылке добавлено (или обновлено, если уже были).
    subscriptions: usize,
    /// Что не добавилось — по строке на подписку или на ключи, без ссылок и токенов.
    failed: Vec<String>,
}

impl AddReport {
    fn merge(&mut self, a: Added) {
        if self.group.is_none() {
            self.group = Some(a.group);
            self.first = a.first;
        }
        self.servers += a.servers;
    }
}

/// Любая вставка из панели «+»: одна или несколько ссылок на подписки (в том числе
/// внутри текста), ключи, base64, конфиги Xray и sing-box — или всё вперемешку.
/// Ошибка — только если не добавилось ничего; иначе неудачи перечислены в `failed`.
#[tauri::command]
pub async fn add_input(
    input: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AddReport, String> {
    if input.len() > MAX_BODY_BYTES {
        return Err(
            kvt_core::i18n::tr("Вставка слишком большая", "The pasted text is too large").into(),
        );
    }
    let split = split_input(&input);
    let has_keys = !split.rest.trim().is_empty();
    let many_urls = split.urls.len() > 1;
    let mut report = AddReport {
        group: None,
        first: None,
        servers: 0,
        subscriptions: 0,
        failed: Vec::new(),
    };
    let mut first_error = None;
    for (i, url) in split.urls.iter().enumerate() {
        // Первая ссылка — сразу; следующие могут подождать очереди к тому же серверу.
        match add_url(&state, url, i > 0).await {
            Ok(a) => {
                report.subscriptions += 1;
                report.merge(a);
            }
            Err(e) => {
                report.failed.push(if many_urls {
                    kvt_core::trf!("Подписка {}: {e}", "Subscription {}: {e}", i + 1)
                } else {
                    e.to_string()
                });
                first_error.get_or_insert(e);
            }
        }
    }
    if has_keys {
        match add_pasted(&state, &split.rest) {
            Ok(a) => report.merge(a),
            Err(e) => {
                report.failed.push(if split.urls.is_empty() {
                    e.to_string()
                } else {
                    kvt_core::trf!("Ключи: {e}", "Keys: {e}")
                });
                first_error.get_or_insert(e);
            }
        }
    }
    if report.group.is_none() {
        return Err(first_error.map(String::from).unwrap_or_else(|| {
            kvt_core::i18n::tr(
                "Не нашлось ни ссылки на подписку, ни ключей. Скопируйте ссылку из личного кабинета провайдера целиком.",
                "No subscription link or keys found. Copy the whole link from your provider's account page.",
            )
            .into()
        }));
    }
    notify(&app);
    Ok(report)
}

/// Своё название подписки (пустое — снова от провайдера). Меняется и в списке на
/// главной, и в трее.
#[tauri::command]
pub fn rename_subscription(
    id: String,
    title: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let title = title.trim();
    if title.chars().count() > 80 || title.chars().any(char::is_control) {
        return Err(kvt_core::i18n::tr(
            "Название длиннее 80 символов или с непечатаемыми символами.",
            "The name is longer than 80 characters or has non-printable characters.",
        )
        .into());
    }
    let found = with_store(&state, |s| s.rename(&id, title))?;
    if !found {
        return Err(SubsError::Gone.into());
    }
    rebuild(&state)?;
    crate::tray::invalidate(&app);
    notify(&app);
    Ok(())
}

/// Как добавилась подписка при переносе из другого клиента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Imported {
    /// Загружена, серверы на месте.
    Loaded,
    /// Сохранена, но сейчас не загрузилась — обновится позже сама.
    Pending,
    /// Такая ссылка в KVT уже есть.
    Existing,
}

/// Подписка из другого клиента. Если загрузить её сейчас нельзя (например, сайт
/// провайдера заблокирован без VPN), ссылка всё равно сохраняется: подписка
/// появится в списке и обновится при следующей возможности.
pub(crate) async fn import_url(
    state: &AppState,
    raw: &str,
    name: &str,
) -> Result<Imported, SubsError> {
    let url = fetch::validate_url(raw)?;
    let exists = state
        .store
        .lock()
        .map_err(lock_err)?
        .as_ref()
        .is_some_and(|s| {
            s.subscriptions
                .iter()
                .any(|x| x.url.as_ref().map(Secret::expose) == Some(url.as_str()))
        });
    if exists {
        return Ok(Imported::Existing);
    }
    let loaded = async {
        let host = url.host_str().unwrap_or_default();
        fetch::acquire(&state.governor, host)?;
        let plan = Plan::of(state, |_| false)?;
        let fetched = fetch::fetch(&url, &plan.hints(host, None)?.hints(&state.governor)).await?;
        ensure_servers(&fetched.body)?;
        Ok::<_, SubsError>(fetched)
    }
    .await;
    match loaded {
        Ok(fetched) => {
            with_store(state, |s| {
                let id = s.add(
                    Some(Secret::new(url.as_str())),
                    fetched.body,
                    fetched.meta,
                    now(),
                );
                s.set_source(&id, fetched.agent, fetched.validators, fetched.hwid_sent);
            })?;
            Ok(Imported::Loaded)
        }
        Err(e) => {
            let meta = SubscriptionMeta {
                title: Some(name.to_owned()).filter(|n| !n.trim().is_empty()),
                ..SubscriptionMeta::default()
            };
            with_store(state, |s| {
                let id = s.add(Some(Secret::new(url.as_str())), String::new(), meta, now());
                s.postpone(&id, now(), Some(&e.to_string()));
            })?;
            Ok(Imported::Pending)
        }
    }
}

/// Ссылки на серверы из другого клиента — в группу «Добавлено вручную».
/// Возвращает, сколько серверов стало доступно.
pub(crate) fn import_links(state: &AppState, links: &[&str]) -> Result<usize, SubsError> {
    if links.is_empty() {
        return Ok(0);
    }
    let body = links.join("\n");
    let count = parse_subscription_body(&body).servers.len();
    if count > 0 {
        with_store(state, |s| {
            s.add(None, body, SubscriptionMeta::default(), now())
        })?;
    }
    Ok(count)
}

pub(crate) fn changed(app: &AppHandle, state: &AppState) -> Result<(), SubsError> {
    rebuild(state)?;
    notify(app);
    Ok(())
}
