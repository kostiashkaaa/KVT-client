//! Подписки: добавление, удаление, ручное и фоновое обновление.

use crate::store::Store;
use crate::{catalog, disconnect_service, display_name, fetch, query_status, watchdog, AppState};
use kvt_core::ipc::ServiceStatus;
use kvt_core::parser::{normalize_pasted, parse_subscription_body};
use kvt_core::subscription::{split_input, SubscriptionMeta, MAX_BODY_BYTES};
use kvt_core::Secret;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

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
    state.user_acted();
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
        .and_then(|s| servers.iter().find(|e| e.sub == id && e.server == *s))
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

/// Ключи, вставленные вручную (ссылки на серверы, base64 или конфиги), — в группу
/// «Добавлено вручную».
fn add_pasted(state: &AppState, body: &str) -> Result<Added, String> {
    // В ручной группе — только ссылки: base64 раскрыт, конфиги Xray и sing-box переведены.
    let body = normalize_pasted(body);
    ensure_servers(&body)?;
    let id = with_store(state, |s| {
        s.add(None, body.clone(), SubscriptionMeta::default(), now())
    })?;
    added(state, id, &body)
}

/// Подписка по ссылке. Та же ссылка второй раз — обновление прежней подписки.
async fn add_url(state: &AppState, raw: &str, patient: bool) -> Result<Added, String> {
    let url = fetch::validate_url(raw)?;
    let host = url.host_str().unwrap_or_default();
    if patient {
        fetch::acquire_patiently(&state.governor, host, BATCH_WAIT).await?;
    } else {
        fetch::acquire(&state.governor, host)?;
    }
    let fetched = fetch::fetch(&url).await?;
    ensure_servers(&fetched.body)?;
    let body = fetched.body.clone();
    let id = with_store(state, |s| {
        s.add(
            Some(Secret::new(url.as_str())),
            fetched.body,
            fetched.meta,
            now(),
        )
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
        return Err("Вставка слишком большая".into());
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
                    format!("Подписка {}: {e}", i + 1)
                } else {
                    e.clone()
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
                    e.clone()
                } else {
                    format!("Ключи: {e}")
                });
                first_error.get_or_insert(e);
            }
        }
    }
    if report.group.is_none() {
        return Err(first_error.unwrap_or_else(|| {
            "Не нашлось ни ссылки на подписку, ни ключей. Скопируйте ссылку из личного кабинета провайдера целиком.".into()
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
        return Err("Название длиннее 80 символов или с непечатаемыми символами.".into());
    }
    let found = with_store(&state, |s| s.rename(&id, title))?;
    if !found {
        return Err("Этой подписки уже нет.".into());
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
        Err(e) => {
            let meta = SubscriptionMeta {
                title: Some(name.to_owned()).filter(|n| !n.trim().is_empty()),
                ..SubscriptionMeta::default()
            };
            with_store(state, |s| {
                let id = s.add(Some(Secret::new(url.as_str())), String::new(), meta, now());
                s.postpone(&id, now(), Some(&e));
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
    /// Когда подписка обновится сама (только у подписок по ссылке).
    next_update: Option<u64>,
    /// Название задал пользователь, а не провайдер.
    renamed: bool,
    /// Последнее обновление не удалось: когда и почему (без ссылки).
    last_error: Option<String>,
    failed_at: Option<u64>,
    /// Ссылки и текст провайдера (только https; текст выводится без разметки).
    support_url: Option<String>,
    web_page_url: Option<String>,
    announce: Option<String>,
    /// Служебные строки провайдера («Осталось 10 ГБ»).
    info: Vec<String>,
    /// Сколько серверов каждого протокола — по убыванию.
    protocols: Vec<ProtocolCount>,
    /// Почему часть строк подписки пропущена: причина и сколько раз.
    skipped: Vec<Skipped>,
    /// Точные повторы, которые выброшены.
    duplicates: usize,
    /// Ключи группы «Добавлено вручную» — каждый можно переименовать, заменить или
    /// удалить. У подписок по ссылке пусто: серверы там задаёт провайдер.
    keys: Vec<ManualKey>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolCount {
    protocol: &'static str,
    count: usize,
}

/// Причина пропуска строк. Текст ошибки разбора секретов не содержит: строку
/// подписки он не повторяет (см. `ParseError`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    reason: String,
    count: usize,
}

fn protocol_counts(servers: &[kvt_core::Server]) -> Vec<ProtocolCount> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in servers {
        *counts.entry(s.protocol.kind()).or_default() += 1;
    }
    let mut list: Vec<ProtocolCount> = counts
        .into_iter()
        .map(|(protocol, count)| ProtocolCount { protocol, count })
        .collect();
    list.sort_by_key(|x| std::cmp::Reverse(x.count));
    list
}

fn skipped(errors: &[(usize, kvt_core::parser::ParseError)]) -> Vec<Skipped> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, e) in errors {
        *counts.entry(e.to_string()).or_default() += 1;
    }
    let mut list: Vec<Skipped> = counts
        .into_iter()
        .map(|(reason, count)| Skipped { reason, count })
        .collect();
    list.sort_by_key(|x| std::cmp::Reverse(x.count));
    list
}

/// Ключ, добавленный вручную, для редактирования. Без секретов: ссылка (в ней
/// UUID или пароль) в окно не уходит — её можно только заменить новой.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualKey {
    key: String,
    /// Название целиком, как в ссылке (с флагами-эмодзи) — для правки.
    name: String,
    /// Название без флагов — для списка: Windows рисует флаги-эмодзи буквами.
    title: String,
    /// Страна из флага — для картинки флага.
    flag: Option<String>,
    protocol: &'static str,
    address: String,
    port: u16,
}

#[tauri::command]
pub fn list_subscriptions(state: State<'_, AppState>) -> Result<Vec<SubscriptionItem>, String> {
    let guard = state.store.lock().map_err(lock_err)?;
    let Some(store) = guard.as_ref() else {
        return Ok(Vec::new());
    };
    let entries = state.servers.lock().map_err(lock_err)?;
    Ok(store
        .subscriptions
        .iter()
        .map(|s| {
            let content = parse_subscription_body(s.body.expose());
            SubscriptionItem {
                id: s.id.clone(),
                title: catalog::title(s),
                by_url: s.url.is_some(),
                servers: content.servers.len(),
                used_bytes: s.meta.used_bytes(),
                total_bytes: s.meta.total,
                expire: s.meta.expire,
                updated_at: s.updated_at,
                next_update: s.url.is_some().then_some(s.next_update),
                renamed: s.custom_title.is_some(),
                last_error: s.last_error.as_ref().map(|e| e.message.clone()),
                failed_at: s.last_error.as_ref().map(|e| e.at),
                support_url: s.meta.support_url.clone(),
                web_page_url: s.meta.web_page_url.clone(),
                announce: s.meta.announce.clone(),
                info: content.info.clone(),
                protocols: protocol_counts(&content.servers),
                skipped: skipped(&content.errors),
                duplicates: content.duplicates,
                keys: if s.url.is_some() {
                    Vec::new()
                } else {
                    entries
                        .iter()
                        .filter(|e| e.sub == s.id)
                        .map(|e| {
                            let f = kvt_core::flag::split_flags(&e.server.name);
                            ManualKey {
                                key: e.key.clone(),
                                name: e.server.name.clone(),
                                title: f.name,
                                flag: f.flag,
                                protocol: e.server.protocol.kind(),
                                address: e.server.address.clone(),
                                port: e.server.port,
                            }
                        })
                        .collect()
                },
            }
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

/// Удаляет один сервер из группы «Добавлено вручную». У подписки по ссылке
/// так нельзя: провайдер вернёт сервер при следующем обновлении.
#[tauri::command]
pub async fn remove_server(
    key: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let entry = state.entry(&key).ok_or("Этого сервера уже нет в списке.")?;
    let before = state.selected();
    with_store(&state, |store| {
        let sub = store
            .subscriptions
            .iter_mut()
            .find(|s| s.id == entry.sub)
            .ok_or("Этого сервера уже нет в списке.")?;
        if sub.url.is_some() {
            return Err(
                "Сервер из подписки по ссылке удалить нельзя — провайдер вернёт его при обновлении."
                    .to_string(),
            );
        }
        let body = kvt_core::parser::remove_server(sub.body.expose(), &entry.server)
            .ok_or("Не удалось найти этот ключ среди добавленных вручную.")?;
        if parse_subscription_body(&body).servers.is_empty() {
            // Последний ключ — группа больше не нужна.
            let id = sub.id.clone();
            store.remove(&id);
        } else {
            sub.body = Secret::new(body);
            sub.updated_at = now();
        }
        Ok(())
    })??;
    rebuild(&state)?;
    guard_selected(&app, before).await;
    notify(&app);
    Ok(())
}

/// Меняет ключ из группы «Добавлено вручную»: название и, если вставлена, саму
/// ссылку. Пустое название при новой ссылке — название из неё. Если VPN работает
/// через этот ключ и ссылка изменилась, KVT переподключается с новыми параметрами.
/// Возвращает ключ сервера после правки (он меняется вместе с адресом или портом).
#[tauri::command]
pub async fn edit_server(
    key: String,
    name: String,
    link: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let entry = state.entry(&key).ok_or("Этого сервера уже нет в списке.")?;
    let link = link.map(|l| l.trim().to_owned()).filter(|l| !l.is_empty());
    // Новая ссылка — ровно один сервер (base64 и JSON раскрываются как при добавлении).
    let new_line = match &link {
        Some(raw) => {
            if raw.len() > kvt_core::parser::MAX_URI_LEN * 4 {
                return Err("Ссылка слишком длинная.".into());
            }
            let normalized = normalize_pasted(raw);
            let content = parse_subscription_body(&normalized);
            if content.servers.len() != 1 {
                return Err(if content.servers.is_empty() {
                    "В ссылке не нашлось сервера — проверьте, что она скопирована целиком.".into()
                } else {
                    "Вставьте ссылку на один сервер — чтобы добавить несколько, нажмите «Добавить»."
                        .into()
                });
            }
            normalized
                .lines()
                .find(|l| {
                    matches!(
                        kvt_core::parser::parse_uri(l),
                        Ok(kvt_core::parser::Entry::Server(_))
                    )
                })
                .map(str::to_owned)
                .ok_or("В ссылке не нашлось сервера.")?
        }
        None => String::new(),
    };
    let name = name.trim();
    let changed_link = link.is_some();

    let new_server = with_store(&state, |store| {
        let sub = store
            .subscriptions
            .iter_mut()
            .find(|s| s.id == entry.sub)
            .ok_or("Этого сервера уже нет в списке.")?;
        if sub.url.is_some() {
            return Err(
                "Сервер из подписки по ссылке изменить нельзя — провайдер вернёт прежний при обновлении."
                    .to_string(),
            );
        }
        // Без новой ссылки правится название прежней: её строка — из тела группы.
        let base = if changed_link {
            new_line.clone()
        } else {
            find_line(sub.body.expose(), &entry.server)
                .ok_or("Не удалось найти этот ключ среди добавленных вручную.")?
        };
        let line = if name.is_empty() {
            base
        } else {
            kvt_core::parser::with_name(&base, name)
                .map_err(|e| format!("Название не подходит: {e}."))?
        };
        let server = match kvt_core::parser::parse_uri(&line) {
            Ok(kvt_core::parser::Entry::Server(s)) => *s,
            _ => return Err("Ссылка не разобралась.".to_string()),
        };
        let body = kvt_core::parser::replace_server(sub.body.expose(), &entry.server, &line)
            .ok_or("Не удалось найти этот ключ среди добавленных вручную.")?;
        sub.body = Secret::new(body);
        sub.updated_at = now();
        Ok(server)
    })??;
    rebuild(&state)?;

    let new_key = state
        .servers
        .lock()
        .map_err(lock_err)?
        .iter()
        .find(|e| e.sub == entry.sub && e.server == new_server)
        .map(|e| e.key.clone())
        .ok_or("Ключ сохранился, но не нашёлся в списке — откройте главную заново.")?;

    // Выбор и «Недавние» в трее идут за ключом, даже если он сменился.
    let was_selected = {
        let mut choice = state.choice.lock().map_err(lock_err)?;
        let was_selected = choice.server.as_deref() == Some(key.as_str());
        if new_key != key {
            if was_selected {
                choice.server = Some(new_key.clone());
            }
            for k in &mut choice.recent {
                if *k == key {
                    k.clone_from(&new_key);
                }
            }
            crate::save_choice(&app, &choice)?;
        }
        was_selected
    };
    if new_key != key {
        let _ = app.emit(watchdog::CHOICE_EVENT, ());
    }
    if changed_link
        && was_selected
        && matches!(
            query_status().await,
            Ok(Some(ServiceStatus::Connected { .. }))
        )
    {
        state.user_acted();
        let result = crate::connect_current(&app, true).await;
        crate::tray::refresh(&app).await;
        result?;
    } else {
        crate::tray::invalidate(&app);
    }
    notify(&app);
    Ok(new_key)
}

/// Строка-ссылка сервера `target` в теле группы «Добавлено вручную».
fn find_line(body: &str, target: &kvt_core::Server) -> Option<String> {
    body.split(kvt_core::parser::CHUNK_SEPARATOR)
        .find_map(|chunk| {
            normalize_pasted(chunk)
                .lines()
                .find(|l| {
                    matches!(
                        kvt_core::parser::parse_uri(l),
                        Ok(kvt_core::parser::Entry::Server(s)) if *s == *target
                    )
                })
                .map(str::to_owned)
        })
}

/// Обновляет одну подписку по ссылке. Ошибка не трогает сохранённую версию, а
/// запоминается у подписки. `patient` — подождать очереди к серверу подписки (при
/// обновлении нескольких подряд), а не отказывать сразу.
async fn refresh_one(state: &AppState, id: &str, patient: bool) -> Result<(), String> {
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
        let host = url.host_str().unwrap_or_default();
        if patient {
            fetch::acquire_patiently(&state.governor, host, BATCH_WAIT).await?;
        } else {
            fetch::acquire(&state.governor, host)?;
        }
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
            with_store(state, |s| s.postpone(id, now(), Some(&e)))?;
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
    let result = refresh_one(&state, &id, false).await;
    rebuild(&state)?;
    guard_selected(&app, before).await;
    notify(&app);
    result
}

/// Открывает в браузере поддержку (`support`) или сайт (`site`) провайдера подписки.
/// Адрес берётся из заголовков подписки (только https), окно его не передаёт.
#[tauri::command]
pub fn open_subscription_link(
    id: String,
    which: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let url = {
        let guard = state.store.lock().map_err(lock_err)?;
        let sub = guard
            .as_ref()
            .and_then(|s| s.get(&id))
            .ok_or("Этой подписки уже нет.")?;
        match which.as_str() {
            "support" => sub.meta.support_url.clone(),
            "site" => sub.meta.web_page_url.clone(),
            _ => None,
        }
        .ok_or("Провайдер не указал такой ссылки.")?
    };
    crate::about::shell_open(&url)
}

/// «Обновить все» во вкладке «Подписки». Возвращает, сколько не обновилось: причины
/// видны у каждой подписки.
#[tauri::command]
pub async fn refresh_all_subscriptions(app: AppHandle) -> Result<usize, String> {
    refresh_all(&app).await
}

/// Обновляет все подписки по ссылке (пункт трея). Возвращает, сколько не обновилось.
pub(crate) async fn refresh_all(app: &AppHandle) -> Result<usize, String> {
    let state = app.state::<AppState>();
    let ids: Vec<String> = {
        let guard = state.store.lock().map_err(lock_err)?;
        guard
            .as_ref()
            .map(|s| {
                s.subscriptions
                    .iter()
                    .filter(|s| s.url.is_some())
                    .map(|s| s.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = state.selected();
    let mut failed = 0;
    for id in &ids {
        if let Err(e) = refresh_one(&state, id, true).await {
            tracing::warn!(error = %e, "подписка не обновилась");
            failed += 1;
        }
    }
    rebuild(&state)?;
    guard_selected(app, before).await;
    notify(app);
    Ok(failed)
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
                    if let Err(e) = refresh_one(&state, id, true).await {
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
