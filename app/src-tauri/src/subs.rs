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

/// Кто убрал сервер из списка.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gone {
    /// Пользователь: удалил подписку или ключ, скрыл фильтром.
    ByUser,
    /// Провайдер: обновление подписки.
    ByProvider,
}

/// Выбранный сервер пропал из списка.
///
/// Провайдер часто меняет у сервера адрес или порт (ключ из них) или добавляет к
/// точке второй вариант — тогда выбор переходит на тот же сервер в новой подписке, а
/// если VPN подключён, KVT переподключается к нему. Если провайдер убрал сервер
/// совсем, а автопереключение включено, KVT подключается к рабочей замене, как при
/// сбое. Иначе — и всегда, если сервер убрал сам пользователь, — KVT отключается и
/// говорит об этом, а не переподключается молча к серверу другой подписки.
async fn guard_selected(app: &AppHandle, before: Option<catalog::Entry>, gone: Gone) {
    let Some(entry) = before else { return };
    let state = app.state::<AppState>();
    if state.entry(&entry.key).is_some() {
        return;
    }
    // Автопереключение могло как раз перебирать серверы: ждём его и смотрим заново —
    // если выбор уже другой, этот сервер больше не наш.
    let _switching = state.switching.lock().await;
    let still_selected = state
        .choice
        .lock()
        .is_ok_and(|c| c.server.as_deref() == Some(entry.key.as_str()));
    if !still_selected || state.entry(&entry.key).is_some() {
        return;
    }
    let connected = matches!(
        query_status().await,
        Ok(Some(ServiceStatus::Connected { .. }))
    );
    if gone == Gone::ByProvider {
        let next = {
            let entries = state.servers.lock().map(|s| s.clone()).unwrap_or_default();
            catalog::successor(&entries, &entry).cloned()
        };
        if let Some(next) = next {
            follow(app, &entry, &next, connected).await;
            return;
        }
    }
    if !connected {
        return;
    }
    let auto = state.choice.lock().map(|c| c.auto_switch).unwrap_or(false);
    // Замена — такая же смена сервера, как автопереключение: лимит общий.
    if gone == Gone::ByProvider
        && auto
        && watchdog::take_incident(&state)
        && replace(app, &entry).await
    {
        return;
    }
    tracing::info!("выбранный сервер исчез из подписок — VPN отключён");
    state.user_disconnected();
    let _ = disconnect_service().await;
    crate::tray::refresh(app).await;
    let _ = app.emit(
        watchdog::EVENT,
        watchdog::Event::ServerRemoved {
            server: display_name(&entry.server),
        },
    );
}

/// Выбор — на тот же сервер с новым ключом. Подключены, и параметры сменились —
/// переподключаемся (kill switch служба держит); если сменился только ключ, ядро
/// трогать незачем.
async fn follow(app: &AppHandle, old: &catalog::Entry, next: &catalog::Entry, connected: bool) {
    let state = app.state::<AppState>();
    let epoch = state.epoch();
    tracing::info!("у выбранного сервера провайдер сменил адрес, порт или вариант — выбран он же");
    // Пользователь мог за время обновления выбрать другой сервер — его выбор не трогаем.
    let moved = crate::update_choice(app, |c| {
        if c.server.as_deref() == Some(old.key.as_str()) {
            c.server = Some(next.key.clone());
        }
    });
    if !matches!(moved, Ok(c) if c.server.as_deref() == Some(next.key.as_str())) {
        return;
    }
    let _ = app.emit(watchdog::CHOICE_EVENT, ());
    if !connected || old.server == next.server {
        return;
    }
    if let Err(e) = crate::connect_auto(app, epoch, true).await {
        tracing::warn!(error = %e, "переподключение к обновлённому серверу не удалось");
    }
    crate::tray::refresh(app).await;
}

/// Провайдер убрал сервер, через который подключены: подключаемся к рабочей замене,
/// как автопереключение при сбое (сначала из той же подписки). `false` — замены нет
/// или пользователь вмешался; выбор тогда возвращается на прежний ключ.
async fn replace(app: &AppHandle, old: &catalog::Entry) -> bool {
    let state = app.state::<AppState>();
    let epoch = state.epoch();
    let from = display_name(&old.server);
    // Последний кандидат, через которого данные не пошли (он записан в выбор).
    let mut failed: Option<String> = None;
    for key in watchdog::alternatives(&state, Some(old)).await {
        if state.epoch() != epoch {
            watchdog::revert_failed(app, failed.as_deref(), Some(&old.key));
            return true;
        }
        if watchdog::switch_to(app, &key, epoch).await.is_ok() {
            if state.epoch() == epoch {
                let to = watchdog::server_name(&state, &key);
                tracing::info!("выбранный сервер исчез из подписки — подключена замена");
                let _ = app.emit(
                    watchdog::EVENT,
                    watchdog::Event::ServerReplaced { from, to },
                );
            }
            return true;
        }
        failed = Some(key);
    }
    if state.epoch() != epoch {
        watchdog::revert_failed(app, failed.as_deref(), Some(&old.key));
        return true;
    }
    let _ = crate::update_choice(app, |c| c.server = Some(old.key.clone()));
    let _ = app.emit(watchdog::CHOICE_EVENT, ());
    false
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
    let store = guard.as_mut().ok_or(kvt_core::i18n::tr(
        "хранилище подписок не загружено",
        "the subscription store isn't loaded",
    ))?;
    let result = f(store);
    store.save().map_err(|e| {
        crate::errors::io(
            kvt_core::i18n::tr(
                "Не удалось сохранить подписки",
                "Couldn't save subscriptions",
            ),
            &e,
        )
    })?;
    Ok(result)
}

fn ensure_servers(body: &str) -> Result<(), String> {
    if parse_subscription_body(body).servers.is_empty() {
        return Err(kvt_core::i18n::tr(
            "В подписке не нашлось ни одного сервера.",
            "No servers found in the subscription.",
        )
        .into());
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
    // Та же ссылка второй раз — с настройками прежней подписки.
    let plan = Plan::of(state, |s| {
        s.url.as_ref().map(Secret::expose) == Some(url.as_str())
    })?;
    let fetched = fetch::fetch(&url, &plan.hints(host, None)?.hints()).await?;
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
                    kvt_core::trf!("Ключи: {e}", "Keys: {e}")
                });
                first_error.get_or_insert(e);
            }
        }
    }
    if report.group.is_none() {
        return Err(first_error.unwrap_or_else(|| {
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
        return Err(kvt_core::i18n::tr(
            "Этой подписки уже нет.",
            "This subscription no longer exists.",
        )
        .into());
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
        let host = url.host_str().unwrap_or_default();
        fetch::acquire(&state.governor, host)?;
        let plan = Plan::of(state, |_| false)?;
        let fetched = fetch::fetch(&url, &plan.hints(host, None)?.hints()).await?;
        ensure_servers(&fetched.body)?;
        Ok::<_, String>(fetched)
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
    /// Что KVT у части серверов не применяет (например, `pinSHA256`): текст и
    /// сколько серверов. Сервер подключается, но пользователь знает, чем рискует.
    warnings: Vec<Skipped>,
    /// Ключи группы «Добавлено вручную» — каждый можно переименовать, заменить или
    /// удалить. У подписок по ссылке пусто: серверы там задаёт провайдер.
    keys: Vec<ManualKey>,
    /// Сколько серверов скрыл фильтр из «Расширенных».
    hidden: usize,
    options: OptionsView,
}

/// «Расширенные» подписки для окна. Свой ID устройства не показывается — только
/// то, что он задан.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionsView {
    keep: Vec<String>,
    drop: Vec<String>,
    client: Option<String>,
    user_agent: Option<String>,
    hwid: HwidMode,
    own_hwid: bool,
    /// ID устройства уходит провайдеру: он его попросил или так выбрано.
    hwid_sent: bool,
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

fn warnings(servers: &[kvt_core::Server]) -> Vec<Skipped> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for w in servers.iter().flat_map(kvt_core::Server::warnings) {
        *counts.entry(w).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(reason, count)| Skipped {
            reason: reason.to_owned(),
            count,
        })
        .collect()
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
    /// Транспорт (`tcp`, `xhttp`…): адрес сервера в окно не уходит.
    transport: &'static str,
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
            let (content, hidden) = catalog::content(s);
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
                warnings: warnings(&content.servers),
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
                                transport: catalog::transport_kind(&e.server.transport),
                            }
                        })
                        .collect()
                },
                hidden,
                options: OptionsView {
                    keep: s.options.filter.keep.clone(),
                    drop: s.options.filter.drop.clone(),
                    client: s.options.client.clone(),
                    user_agent: s.options.user_agent.clone(),
                    hwid: s.options.hwid,
                    own_hwid: s.own_hwid.is_some(),
                    hwid_sent: match s.options.hwid {
                        HwidMode::Always => true,
                        HwidMode::Auto => s.hwid_asked,
                        HwidMode::Never => false,
                    },
                },
            }
        })
        .collect())
}

/// «Расширенные» из окна.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionsInput {
    /// Слова через запятую — как ввёл пользователь.
    keep: String,
    drop: String,
    /// `None` — «Авто», иначе ключ из `fetch::PROFILES` или `custom`.
    client: Option<String>,
    user_agent: String,
    hwid: HwidMode,
    /// `None` — не менять, пустая строка — убрать свой ID.
    own_hwid: Option<String>,
}

const MAX_USER_AGENT: usize = 200;
const MAX_HWID: usize = 128;

fn parse_options(input: OptionsInput) -> Result<(SubOptions, OwnHwid), String> {
    let filter = NameFilter::parse(&input.keep, &input.drop)?;
    let custom = input.client.as_deref() == Some(fetch::CUSTOM);
    let user_agent = if custom {
        Some(header_value(&input.user_agent, MAX_USER_AGENT).ok_or(
            kvt_core::i18n::tr("User-Agent пустой, длиннее 200 символов или не латиницей — проверьте строку.", "The User-Agent is empty, longer than 200 characters or not in Latin script — check it."),
        )?)
    } else {
        None
    };
    if let Some(c) = input.client.as_deref() {
        if !custom && !fetch::PROFILES.contains(&c) {
            return Err(kvt_core::i18n::tr(
                "Такого клиента KVT не знает.",
                "KVT doesn't know this client.",
            )
            .into());
        }
    }
    let own = match input.own_hwid.as_deref().map(str::trim) {
        None => OwnHwid::Keep,
        Some("") => OwnHwid::Clear,
        Some(raw) => OwnHwid::Set(header_value(raw, MAX_HWID).ok_or(
            kvt_core::i18n::tr("ID устройства длиннее 128 символов или не латиницей — скопируйте его у провайдера целиком.", "The device ID is longer than 128 characters or not in Latin script — copy it from your provider in full."),
        )?),
    };
    Ok((
        SubOptions {
            filter,
            client: input.client,
            user_agent,
            hwid: input.hwid,
        },
        own,
    ))
}

/// Сохраняет «Расширенные» подписки. Если сменился клиент или ID устройства,
/// подписка по ссылке сразу загружается заново — ошибка загрузки возвращается, но
/// настройки остаются сохранёнными (причина видна у подписки).
#[tauri::command]
pub async fn set_subscription_options(
    id: String,
    options: OptionsInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let (options, own) = parse_options(options)?;
    let before = state.selected();
    let (request_changed, by_url) = with_store(&state, |s| {
        let changed = s.set_options(&id, options, own);
        (changed, s.get(&id).is_some_and(|x| x.url.is_some()))
    })?;
    let request_changed = request_changed.ok_or(kvt_core::i18n::tr(
        "Этой подписки уже нет.",
        "This subscription no longer exists.",
    ))?;
    let result = if request_changed && by_url {
        refresh_one(&state, &id, Refresh::Now).await
    } else {
        Ok(())
    };
    rebuild(&state)?;
    crate::tray::invalidate(&app);
    guard_selected(&app, before, Gone::ByUser).await;
    notify(&app);
    result
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
    guard_selected(&app, before, Gone::ByUser).await;
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
    let entry = state.entry(&key).ok_or(kvt_core::i18n::tr(
        "Этого сервера уже нет в списке.",
        "This server is no longer in the list.",
    ))?;
    let before = state.selected();
    with_store(&state, |store| {
        let sub = store
            .subscriptions
            .iter_mut()
            .find(|s| s.id == entry.sub)
            .ok_or(kvt_core::i18n::tr(
                "Этого сервера уже нет в списке.",
                "This server is no longer in the list.",
            ))?;
        if sub.url.is_some() {
            return Err(kvt_core::i18n::tr(
                "Сервер из подписки по ссылке удалить нельзя — провайдер вернёт его при обновлении.",
                "A server from a link subscription can't be removed — the provider will bring it back on update.",
            )
            .to_string());
        }
        let body = kvt_core::parser::remove_server(sub.body.expose(), &entry.server).ok_or(
            kvt_core::i18n::tr(
                "Не удалось найти этот ключ среди добавленных вручную.",
                "Couldn't find this key among the manually added ones.",
            ),
        )?;
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
    guard_selected(&app, before, Gone::ByUser).await;
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
    let entry = state.entry(&key).ok_or(kvt_core::i18n::tr(
        "Этого сервера уже нет в списке.",
        "This server is no longer in the list.",
    ))?;
    let link = link.map(|l| l.trim().to_owned()).filter(|l| !l.is_empty());
    // Новая ссылка — ровно один сервер (base64 и JSON раскрываются как при добавлении).
    let new_line = match &link {
        Some(raw) => {
            if raw.len() > kvt_core::parser::MAX_URI_LEN * 4 {
                return Err(
                    kvt_core::i18n::tr("Ссылка слишком длинная.", "The link is too long.").into(),
                );
            }
            let normalized = normalize_pasted(raw);
            let content = parse_subscription_body(&normalized);
            if content.servers.len() != 1 {
                return Err(if content.servers.is_empty() {
                    kvt_core::i18n::tr(
                        "В ссылке не нашлось сервера — проверьте, что она скопирована целиком.",
                        "No server found in the link — check that it was copied in full.",
                    )
                    .into()
                } else {
                    kvt_core::i18n::tr(
                        "Вставьте ссылку на один сервер — чтобы добавить несколько, нажмите «Добавить».",
                        "Paste a link to one server — to add several, press “Add”.",
                    )
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
                .ok_or(kvt_core::i18n::tr(
                    "В ссылке не нашлось сервера.",
                    "No server found in the link.",
                ))?
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
            .ok_or(kvt_core::i18n::tr(
                "Этого сервера уже нет в списке.",
                "This server is no longer in the list.",
            ))?;
        if sub.url.is_some() {
            return Err(kvt_core::i18n::tr(
                "Сервер из подписки по ссылке изменить нельзя — провайдер вернёт прежний при обновлении.",
                "A server from a link subscription can't be edited — the provider will restore it on update.",
            )
            .to_string());
        }
        // Без новой ссылки правится название прежней: её строка — из тела группы.
        let base = if changed_link {
            new_line.clone()
        } else {
            find_line(sub.body.expose(), &entry.server).ok_or(kvt_core::i18n::tr(
                "Не удалось найти этот ключ среди добавленных вручную.",
                "Couldn't find this key among the manually added ones.",
            ))?
        };
        let line = if name.is_empty() {
            base
        } else {
            kvt_core::parser::with_name(&base, name).map_err(|e| {
                kvt_core::trf!("Название не подходит: {e}.", "The name doesn't fit: {e}.")
            })?
        };
        let server = match kvt_core::parser::parse_uri(&line) {
            Ok(kvt_core::parser::Entry::Server(s)) => *s,
            _ => {
                return Err(
                    kvt_core::i18n::tr("Ссылка не разобралась.", "Couldn't read the link.")
                        .to_string(),
                )
            }
        };
        let body = kvt_core::parser::replace_server(sub.body.expose(), &entry.server, &line)
            .ok_or(kvt_core::i18n::tr(
                "Не удалось найти этот ключ среди добавленных вручную.",
                "Couldn't find this key among the manually added ones.",
            ))?;
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
        .ok_or(kvt_core::i18n::tr(
            "Ключ сохранился, но не нашёлся в списке — откройте главную заново.",
            "The key was saved but isn't in the list — reopen the home page.",
        ))?;

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

/// Как обновляется подписка.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refresh {
    /// Кнопка «Обновить» у одной подписки: сразу и целиком — пользователь ждёт
    /// свежий трафик и срок, а не «не изменилась».
    Now,
    /// «Обновить все» и трей: подождать очереди к серверу подписки (несколько
    /// подписок одного провайдера подряд), но тоже целиком.
    Batch,
    /// По расписанию: в очереди и с вопросом «изменилась ли» (ETag / Last-Modified).
    Scheduled,
}

/// Обновляет одну подписку по ссылке. Ошибка не трогает сохранённую версию, а
/// запоминается у подписки.
async fn refresh_one(state: &AppState, id: &str, how: Refresh) -> Result<(), String> {
    let (url, plan) = {
        let guard = state.store.lock().map_err(lock_err)?;
        let url = guard
            .as_ref()
            .and_then(|s| s.get(id))
            .and_then(|s| s.url.clone())
            .ok_or(kvt_core::i18n::tr(
                "У этой подписки нет ссылки для обновления",
                "This subscription has no update link",
            ))?;
        drop(guard);
        let mut plan = Plan::of(state, |s| s.id == id)?;
        // Метки — только по расписанию и у непустого тела: подписка, добавленная
        // без ответа провайдера, должна загрузиться целиком.
        if how != Refresh::Scheduled || plan.empty_body {
            plan.validators = None;
        }
        (url, plan)
    };
    let url = fetch::validate_url(url.expose())?;
    let result = async {
        let host = url.host_str().unwrap_or_default();
        if how == Refresh::Now {
            fetch::acquire(&state.governor, host)?;
        } else {
            fetch::acquire_patiently(&state.governor, host, BATCH_WAIT).await?;
        }
        let request = plan.hints(host, plan.agent.as_deref())?;
        let loaded = fetch::load(&url, &request.hints()).await?;
        if let fetch::Loaded::Fresh(fetched) = &loaded {
            ensure_servers(&fetched.body)?;
        }
        Ok::<_, String>(loaded)
    }
    .await;
    match result {
        Ok(fetch::Loaded::Fresh(fetched)) => {
            with_store(state, |s| {
                s.update(id, fetched.body, fetched.meta, now());
                s.set_source(id, fetched.agent, fetched.validators, fetched.hwid_sent);
            })?;
            Ok(())
        }
        Ok(fetch::Loaded::NotModified(meta)) => {
            with_store(state, |s| s.not_modified(id, meta, now()))?;
            Ok(())
        }
        Err(e) => {
            with_store(state, |s| s.postpone(id, now(), Some(&e)))?;
            Err(e)
        }
    }
}

/// Как спрашивать провайдера: настройки подписки и что запомнено с прошлого раза.
/// Собирается под блокировкой хранилища, используется уже без неё.
#[derive(Default)]
struct Plan {
    options: SubOptions,
    own_hwid: Option<Secret>,
    hwid_asked: bool,
    agent: Option<String>,
    validators: Option<Validators>,
    empty_body: bool,
    dir: Option<PathBuf>,
}

/// Готовые значения для `fetch::Hints` (они только заимствуют).
struct Request<'a> {
    plan: &'a Plan,
    agent: Option<&'a str>,
    hwid: Option<String>,
}

impl Plan {
    /// Настройки подписки, подходящей под `find`; нет такой — по умолчанию.
    fn of(state: &AppState, find: impl Fn(&Subscription) -> bool) -> Result<Plan, String> {
        let guard = state.store.lock().map_err(lock_err)?;
        let Some(store) = guard.as_ref() else {
            return Ok(Plan::default());
        };
        let dir = store.dir().map(PathBuf::from);
        Ok(match store.subscriptions.iter().find(|s| find(s)) {
            Some(s) => Plan {
                options: s.options.clone(),
                own_hwid: s.own_hwid.clone(),
                hwid_asked: s.hwid_asked,
                agent: s.agent.clone(),
                validators: s.validators.clone(),
                empty_body: s.body.expose().is_empty(),
                dir,
            },
            None => Plan {
                dir,
                ..Plan::default()
            },
        })
    }

    /// ID устройства для провайдера `host`: свой от провайдера или производный от
    /// секрета установки (`device`).
    fn hints<'a>(&'a self, host: &str, agent: Option<&'a str>) -> Result<Request<'a>, String> {
        let mode = self.options.hwid;
        let hwid = if mode == HwidMode::Never {
            None
        } else if let Some(own) = &self.own_hwid {
            Some(own.expose().to_owned())
        } else {
            match self.dir.as_deref().map(|d| crate::device::hwid(d, host)) {
                Some(Ok(id)) => Some(id),
                Some(Err(e)) if mode == HwidMode::Always => {
                    return Err(crate::errors::io(
                        kvt_core::i18n::tr(
                            "Не удалось прочитать ID устройства",
                            "Couldn't read the device ID",
                        ),
                        &e,
                    ))
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "ID устройства недоступен");
                    None
                }
                None => None,
            }
        };
        Ok(Request {
            plan: self,
            agent,
            hwid,
        })
    }
}

impl Request<'_> {
    fn hints(&self) -> fetch::Hints<'_> {
        let options = &self.plan.options;
        let client = match (options.client.as_deref(), options.user_agent.as_deref()) {
            (Some(fetch::CUSTOM), Some(agent)) => fetch::Client::Custom(agent),
            (Some(fetch::CUSTOM), None) | (None, _) => fetch::Client::Auto,
            (Some(key), _) => fetch::Client::Profile(key),
        };
        let hwid = match (&self.hwid, options.hwid) {
            (None, _) | (_, HwidMode::Never) => fetch::Hwid::Off,
            (Some(id), HwidMode::Always) => fetch::Hwid::Send(id),
            (Some(id), HwidMode::Auto) if self.plan.hwid_asked => fetch::Hwid::Send(id),
            (Some(id), HwidMode::Auto) => fetch::Hwid::OnRequest(id),
        };
        fetch::Hints {
            client,
            agent: self.agent,
            validators: self.plan.validators.as_ref(),
            hwid,
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
    let result = refresh_one(&state, &id, Refresh::Now).await;
    rebuild(&state)?;
    guard_selected(&app, before, Gone::ByProvider).await;
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
            .ok_or(kvt_core::i18n::tr(
                "Этой подписки уже нет.",
                "This subscription no longer exists.",
            ))?;
        match which.as_str() {
            "support" => sub.meta.support_url.clone(),
            "site" => sub.meta.web_page_url.clone(),
            _ => None,
        }
        .ok_or(kvt_core::i18n::tr(
            "Провайдер не указал такой ссылки.",
            "The provider didn't specify such a link.",
        ))?
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
        if let Err(e) = refresh_one(&state, id, Refresh::Batch).await {
            tracing::warn!(error = %e, "подписка не обновилась");
            failed += 1;
        }
    }
    rebuild(&state)?;
    guard_selected(app, before, Gone::ByProvider).await;
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
                    if let Err(e) = refresh_one(&state, id, Refresh::Scheduled).await {
                        tracing::warn!(error = %e, "подписка не обновилась");
                    }
                }
                let _ = rebuild(&state);
                guard_selected(&app, before, Gone::ByProvider).await;
                notify(&app);
            }
            tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        }
    });
}
