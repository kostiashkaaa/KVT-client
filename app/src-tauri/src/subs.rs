//! Подписки: добавление, удаление, ручное и фоновое обновление.

use crate::store::Store;
use crate::{catalog, disconnect_service, display_name, fetch, query_status, watchdog, AppState};
use kvt_core::ipc::ServiceStatus;
use kvt_core::parser::parse_subscription_body;
use kvt_core::subscription::{SubscriptionMeta, MAX_BODY_BYTES};
use kvt_core::Secret;
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

/// Событие для интерфейса: подписки или их серверы изменились.
pub const CHANGED_EVENT: &str = "subscriptions-changed";
const STORE_FILE: &str = "subscriptions.json";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lock_err<T>(e: T) -> String {
    crate::errors::state(e)
}

pub fn load(app: &AppHandle) -> Result<Store, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(Store::load(dir.join(STORE_FILE)))
}

/// Пересобирает единый список серверов и группы для интерфейса.
pub fn rebuild(state: &AppState) -> Result<(), String> {
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
    // Адреса серверов не должны попасть в журналы и экспорт диагностики.
    kvt_core::redact::set_servers(entries.iter().map(|e| e.server.address.as_str()));
    *state.servers.lock().map_err(lock_err)? = entries;
    *state.groups.lock().map_err(lock_err)? = groups;
    Ok(())
}

/// Сервер, к которому подключены, пропал из подписок (подписку удалили или
/// провайдер убрал сервер). KVT отключается и говорит об этом, а не
/// переподключается молча к первому серверу другой подписки.
async fn guard_selected(app: &AppHandle, before: Option<catalog::Entry>) {
    let Some(entry) = before else { return };
    let state = app.state::<AppState>();
    if state.entry(&entry.key).is_some() {
        return;
    }
    if !matches!(
        query_status().await,
        Ok(Some(ServiceStatus::Connected { .. }))
    ) {
        return;
    }
    tracing::info!("выбранный сервер исчез из подписок — VPN отключён");
    let _ = disconnect_service().await;
    crate::tray::refresh(app).await;
    let _ = app.emit(
        watchdog::EVENT,
        watchdog::Event::ServerRemoved {
            server: display_name(&entry.server),
        },
    );
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
fn added(state: &AppState, id: String, body: &str) -> Result<Added, String> {
    rebuild(state)?;
    let new = parse_subscription_body(body).servers;
    let servers = state.servers.lock().map_err(lock_err)?;
    let first = new
        .first()
        .and_then(|s| {
            let key = catalog::key(&id, s);
            servers.iter().find(|e| e.key == key)
        })
        .or_else(|| servers.iter().find(|e| e.sub == id))
        .map(|e| e.key.clone());
    Ok(Added {
        group: id,
        first,
        servers: new.len(),
    })
}

fn with_store<R>(state: &AppState, f: impl FnOnce(&mut Store) -> R) -> Result<R, String> {
    let mut guard = state.store.lock().map_err(lock_err)?;
    let store = guard.as_mut().ok_or("хранилище подписок не загружено")?;
    let result = f(store);
    store
        .save()
        .map_err(|e| crate::errors::io("Не удалось сохранить подписки", &e))?;
    Ok(result)
}

fn ensure_servers(body: &str) -> Result<(), String> {
    if parse_subscription_body(body).servers.is_empty() {
        return Err("В подписке не нашлось ни одного сервера.".into());
    }
    Ok(())
}

fn notify(app: &AppHandle) {
    let _ = app.emit(CHANGED_EVENT, ());
}

/// Подписка, вставленная вручную (ссылки на серверы или содержимое).
#[tauri::command]
pub fn parse_subscription(
    body: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Added, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err("Подписка слишком большая".into());
    }
    ensure_servers(&body)?;
    let id = with_store(&state, |s| {
        s.add(None, body.clone(), SubscriptionMeta::default(), now())
    })?;
    let result = added(&state, id, &body)?;
    notify(&app);
    Ok(result)
}

#[tauri::command]
pub async fn add_subscription_url(
    url: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Added, String> {
    let url = fetch::validate_url(&url)?;
    fetch::acquire(&state.governor, url.host_str().unwrap_or_default())?;
    let fetched = fetch::fetch(&url).await?;
    ensure_servers(&fetched.body)?;
    let body = fetched.body.clone();
    let id = with_store(&state, |s| {
        s.add(
            Some(Secret::new(url.as_str())),
            fetched.body,
            fetched.meta,
            now(),
        )
    })?;
    let result = added(&state, id, &body)?;
    notify(&app);
    Ok(result)
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
) -> Result<Imported, String> {
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
        fetch::acquire(&state.governor, url.host_str().unwrap_or_default())?;
        let fetched = fetch::fetch(&url).await?;
        ensure_servers(&fetched.body)?;
        Ok::<_, String>(fetched)
    }
    .await;
    match loaded {
        Ok(fetched) => {
            with_store(state, |s| {
                s.add(
                    Some(Secret::new(url.as_str())),
                    fetched.body,
                    fetched.meta,
                    now(),
                )
            })?;
            Ok(Imported::Loaded)
        }
        Err(_) => {
            let meta = SubscriptionMeta {
                title: Some(name.to_owned()).filter(|n| !n.trim().is_empty()),
                ..SubscriptionMeta::default()
            };
            with_store(state, |s| {
                let id = s.add(Some(Secret::new(url.as_str())), String::new(), meta, now());
                s.postpone(&id, now());
            })?;
            Ok(Imported::Pending)
        }
    }
}

/// Ссылки на серверы из другого клиента — в группу «Добавлено вручную».
/// Возвращает, сколько серверов стало доступно.
pub(crate) fn import_links(state: &AppState, links: &[&str]) -> Result<usize, String> {
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

pub(crate) fn changed(app: &AppHandle, state: &AppState) -> Result<(), String> {
    rebuild(state)?;
    notify(app);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionItem {
    id: String,
    title: String,
    by_url: bool,
    servers: usize,
    used_bytes: Option<u64>,
    total_bytes: Option<u64>,
    expire: Option<u64>,
    updated_at: u64,
}

#[tauri::command]
pub fn list_subscriptions(state: State<'_, AppState>) -> Result<Vec<SubscriptionItem>, String> {
    let guard = state.store.lock().map_err(lock_err)?;
    let Some(store) = guard.as_ref() else {
        return Ok(Vec::new());
    };
    Ok(store
        .subscriptions
        .iter()
        .map(|s| SubscriptionItem {
            id: s.id.clone(),
            title: catalog::title(s),
            by_url: s.url.is_some(),
            servers: parse_subscription_body(s.body.expose()).servers.len(),
            used_bytes: s.meta.used_bytes(),
            total_bytes: s.meta.total,
            expire: s.meta.expire,
            updated_at: s.updated_at,
        })
        .collect())
}

#[tauri::command]
pub async fn remove_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let before = state.selected();
    with_store(&state, |s| s.remove(&id))?;
    rebuild(&state)?;
    guard_selected(&app, before).await;
    notify(&app);
    Ok(())
}

/// Обновляет одну подписку по ссылке. Ошибка не трогает сохранённую версию.
async fn refresh_one(state: &AppState, id: &str) -> Result<(), String> {
    let url = {
        let guard = state.store.lock().map_err(lock_err)?;
        guard
            .as_ref()
            .and_then(|s| s.get(id))
            .and_then(|s| s.url.clone())
            .ok_or("У этой подписки нет ссылки для обновления")?
    };
    let url = fetch::validate_url(url.expose())?;
    let result = async {
        fetch::acquire(&state.governor, url.host_str().unwrap_or_default())?;
        let fetched = fetch::fetch(&url).await?;
        ensure_servers(&fetched.body)?;
        Ok::<_, String>(fetched)
    }
    .await;
    match result {
        Ok(fetched) => {
            with_store(state, |s| s.update(id, fetched.body, fetched.meta, now()))?;
            Ok(())
        }
        Err(e) => {
            with_store(state, |s| s.postpone(id, now()))?;
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn refresh_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let before = state.selected();
    let result = refresh_one(&state, &id).await;
    rebuild(&state)?;
    guard_selected(&app, before).await;
    notify(&app);
    result
}

/// Фоновое обновление по расписанию провайдера (`profile-update-interval`,
/// не чаще раза в час, с разбросом). Первая проверка — через минуту после запуска.
pub fn spawn_updater(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let due = app
                .state::<AppState>()
                .store
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.due(now())))
                .unwrap_or_default();
            if !due.is_empty() {
                let state = app.state::<AppState>();
                let before = state.selected();
                for (id, _) in &due {
                    if let Err(e) = refresh_one(&state, id).await {
                        tracing::warn!(error = %e, "подписка не обновилась");
                    }
                }
                let _ = rebuild(&state);
                guard_selected(&app, before).await;
                notify(&app);
            }
            tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        }
    });
}
