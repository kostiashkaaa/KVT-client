//! Подписки: добавление, выбор, удаление, ручное и фоновое обновление.

use crate::store::{Store, Subscription};
use crate::{fetch, AppState, LineError, ParsedSubscription, ServerSummary, SubscriptionInfo};
use kvt_core::parser::parse_subscription_body;
use kvt_core::subscription::{SubscriptionMeta, MAX_BODY_BYTES};
use kvt_core::{Secret, Server};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

/// Событие для интерфейса: список подписок или активная подписка изменились.
pub const CHANGED_EVENT: &str = "subscriptions-changed";
const STORE_FILE: &str = "subscriptions.json";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lock_err<T>(_: T) -> String {
    "внутренняя ошибка состояния".into()
}

pub fn load(app: &AppHandle) -> Result<Store, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(Store::load(dir.join(STORE_FILE)))
}

fn view(sub: &Subscription) -> (ParsedSubscription, Vec<Server>) {
    let content = parse_subscription_body(sub.body.expose());
    let parsed = ParsedSubscription {
        id: Some(sub.id.clone()),
        servers: content.servers.iter().map(ServerSummary::from).collect(),
        info: content.info,
        errors: content
            .errors
            .into_iter()
            .map(|(line, e)| LineError {
                line,
                message: e.to_string(),
            })
            .collect(),
        duplicates: content.duplicates,
        meta: Some(SubscriptionInfo::from(&sub.meta)),
    };
    (parsed, content.servers)
}

/// Пересобирает данные активной подписки (серверы для подключения и вид для интерфейса).
pub fn activate(state: &AppState) -> Result<Option<ParsedSubscription>, String> {
    let view = {
        let store = state.store.lock().map_err(lock_err)?;
        store.as_ref().and_then(Store::active).map(view)
    };
    let (parsed, servers) = match view {
        Some((p, s)) => (Some(p), s),
        None => (None, Vec::new()),
    };
    *state.servers.lock().map_err(lock_err)? = servers;
    *state.last.lock().map_err(lock_err)? = parsed.clone();
    Ok(parsed)
}

fn with_store<R>(state: &AppState, f: impl FnOnce(&mut Store) -> R) -> Result<R, String> {
    let mut guard = state.store.lock().map_err(lock_err)?;
    let store = guard.as_mut().ok_or("хранилище подписок не загружено")?;
    let result = f(store);
    store
        .save()
        .map_err(|e| format!("не удалось сохранить подписки: {e}"))?;
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
) -> Result<ParsedSubscription, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err("Подписка слишком большая".into());
    }
    ensure_servers(&body)?;
    with_store(&state, |s| {
        s.add(None, body, SubscriptionMeta::default(), now())
    })?;
    let parsed = activate(&state)?.ok_or("подписка не сохранилась")?;
    notify(&app);
    Ok(parsed)
}

#[tauri::command]
pub async fn add_subscription_url(
    url: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ParsedSubscription, String> {
    let url = fetch::validate_url(&url)?;
    fetch::acquire(&state.governor, url.host_str().unwrap_or_default())?;
    let fetched = fetch::fetch(&url).await?;
    ensure_servers(&fetched.body)?;
    with_store(&state, |s| {
        s.add(
            Some(Secret::new(url.as_str())),
            fetched.body,
            fetched.meta,
            now(),
        )
    })?;
    let parsed = activate(&state)?.ok_or("подписка не сохранилась")?;
    notify(&app);
    Ok(parsed)
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
    active: bool,
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
            // Хост ссылки не секрет (токен — в пути), им удобно подписать безымянную подписку.
            title: s.meta.title.clone().unwrap_or_else(|| {
                s.url
                    .as_ref()
                    .and_then(|u| url::Url::parse(u.expose()).ok())
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_else(|| "Добавлена вручную".into())
            }),
            by_url: s.url.is_some(),
            servers: parse_subscription_body(s.body.expose()).servers.len(),
            used_bytes: s.meta.used_bytes(),
            total_bytes: s.meta.total,
            expire: s.meta.expire,
            updated_at: s.updated_at,
            active: store.active.as_deref() == Some(s.id.as_str()),
        })
        .collect())
}

#[tauri::command]
pub fn select_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<ParsedSubscription>, String> {
    if !with_store(&state, |s| s.set_active(&id))? {
        return Err("Подписка не найдена".into());
    }
    let parsed = activate(&state)?;
    notify(&app);
    Ok(parsed)
}

#[tauri::command]
pub fn remove_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    with_store(&state, |s| s.remove(&id))?;
    activate(&state)?;
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
    let result = refresh_one(&state, &id).await;
    activate(&state)?;
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
                for (id, _) in &due {
                    if let Err(e) = refresh_one(&state, id).await {
                        eprintln!("подписка не обновилась: {e}");
                    }
                }
                let _ = activate(&state);
                notify(&app);
            }
            tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        }
    });
}
