// Без консольного окна в релизной сборке.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod about;
mod applog;
mod audit;
mod autostart;
mod catalog;
mod diagexport;
mod diagnostics;
mod dnscheck;
mod dpapi;
mod errors;
mod fetch;
mod health;
mod journal;
mod migrate;
mod netinfo;
mod netprofile;
mod notify;
mod power;
mod prober;
mod service_client;
mod settings;
mod store;
mod subs;
mod tray;
mod troubleshoot;
mod tunnel;
mod updates;
mod watchdog;
mod winreg;
mod zapret;

use kvt_core::compile::DnsPlan;
use kvt_core::core_select::{select_core, CoreKind};
use kvt_core::governor::{NetGovernor, NetPolicy};
use kvt_core::ipc::{self, ConnectPlan, Request, Response, ServiceStatus, Session};
use kvt_core::model::{Protocol, Security, Server};
use kvt_core::routing::presets::{self, RoutingSettings};
use kvt_core::subscription::SubscriptionMeta;
use kvt_core::tester::{self, Outcome, QuickResult};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, State};

/// Подписки, серверы и ключи живут в Rust; в WebView уходит только
/// `ServerSummary` без паролей, UUID и токенов.
pub(crate) struct AppState {
    /// Сохранённые подписки (загружаются при старте из каталога данных).
    store: Mutex<Option<store::Store>>,
    /// Серверы всех подписок подряд, с ключами.
    servers: Mutex<Vec<catalog::Entry>>,
    governor: Mutex<NetGovernor>,
    /// Найденное в других клиентах для переноса (со ссылками — только в Rust).
    migration: Mutex<Vec<kvt_core::migrate::Collected>>,
    /// Подписки в виде для интерфейса: окно может быть закрыто (WebView
    /// выгружен), а при открытии интерфейс восстанавливается отсюда.
    groups: Mutex<Vec<catalog::Group>>,
    /// Идёт полная проверка серверов (одновременно — только одна).
    checking: std::sync::atomic::AtomicBool,
    /// Выбранный сервер, режим и kill switch — ими пользуется и трей.
    choice: Mutex<Choice>,
    /// Итоги полной проверки по ключам серверов.
    outcomes: Mutex<HashMap<String, Outcome>>,
    /// Последняя проверка DNS: повтор в течение минуты отдаёт её же.
    dns_report: Mutex<Option<(Instant, kvt_core::dns::DnsReport)>>,
    /// Клиент проверки туннеля: держит соединение открытым между проверками.
    health: reqwest::Client,
    /// Сеть, через которую сейчас идёт трафик.
    network: Mutex<Option<netinfo::Network>>,
    /// Идёт автоподбор стратегии zapret и запрошена ли его отмена.
    zapret_picking: std::sync::atomic::AtomicBool,
    zapret_cancel: std::sync::atomic::AtomicBool,
    /// Последняя проверка zapret (ручная, автоматическая или итог подбора).
    zapret_last: Mutex<Option<zapret::CheckRecord>>,
    /// Последний релиз Flowseal и когда его спрашивали.
    zapret_release: Mutex<Option<(Instant, kvt_core::zapret::Release)>>,
    /// Будит автопроверку zapret раньше срока (смена сети).
    zapret_wake: tokio::sync::Notify,
    /// Сообщения для окна, которые появились до его открытия (например, о
    /// повреждённых настройках). Окно забирает их один раз.
    notices: Mutex<Vec<String>>,
    /// Идут ли данные через туннель: `None` — не проверяли или VPN выключен.
    tunnel: Mutex<Option<bool>>,
    /// Будит автопереключение раньше срока (выход из сна).
    watchdog_wake: tokio::sync::Notify,
    /// Последний итог «Почему не работает?» — для экспорта диагностики.
    last_diagnosis: Mutex<Option<troubleshoot::Diagnosis>>,
    /// Файлы диагностики, которые пользователь видел в предпросмотре.
    diag_files: Mutex<Vec<diagexport::DiagFile>>,
    /// Последний известный сеанс службы (время и трафик) — для главной и трея.
    session: Mutex<Option<Session>>,
    /// Страница, которую трей попросил открыть до появления окна.
    pending_page: Mutex<Option<String>>,
    /// Растёт с каждым подключением и отключением по воле пользователя (окно, трей,
    /// профиль сети). Автоматика, начатая раньше, видит, что её решение устарело.
    epoch: std::sync::atomic::AtomicU64,
}

/// Выбор пользователя. Секретов не содержит, поэтому хранится в settings.json
/// в каталоге настроек приложения.
#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Choice {
    /// Ключ выбранного сервера (`catalog::key`).
    server: Option<String>,
    /// Номер сервера в «основной» подписке — из версий до единого списка.
    /// Читается один раз при запуске и переводится в `server`.
    #[serde(skip_serializing)]
    server_index: Option<i64>,
    mode: Option<String>,
    kill_switch: bool,
    routing: RoutingSettings,
    dns: DnsChoice,
    /// Переключаться на другой сервер, если через текущий перестали идти данные.
    auto_switch: bool,
    networks: Vec<netprofile::NetworkProfile>,
    zapret: zapret::ZapretChoice,
    /// Последние выбранные вручную серверы (для трея). Окно это поле не присылает —
    /// `set_choice` сохраняет прежнее.
    recent: Vec<String>,
    /// Уведомления Windows, пока окно закрыто.
    notifications: bool,
    /// Подключаться к выбранному серверу при запуске KVT.
    connect_on_start: bool,
    /// Узнавать у GitHub, не вышла ли новая версия KVT (`updates`).
    check_updates: bool,
    /// Подсказки первого запуска пройдены или пропущены.
    onboarded: bool,
    /// Автозапуск уже включался при первом запуске установленного KVT: если
    /// пользователь потом его выключил, не включать снова. Окно поле не присылает.
    autostart_offered: bool,
}

/// Сколько серверов помнит «Недавние» в трее.
const RECENT: usize = 5;

impl Choice {
    /// Запоминает ручной выбор сервера для «Недавних».
    fn remember(&mut self, key: &str) {
        self.recent.retain(|k| k != key);
        self.recent.insert(0, key.to_owned());
        self.recent.truncate(RECENT);
    }
}

impl Default for Choice {
    fn default() -> Self {
        Self {
            server: None,
            server_index: None,
            mode: None,
            kill_switch: false,
            routing: RoutingSettings::default(),
            dns: DnsChoice::default(),
            auto_switch: true,
            networks: Vec::new(),
            zapret: zapret::ZapretChoice::default(),
            recent: Vec::new(),
            notifications: true,
            connect_on_start: false,
            check_updates: true,
            onboarded: false,
            autostart_offered: false,
        }
    }
}

/// Резолверы из `kvt_core::dns::RESOLVERS` (по id).
#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DnsChoice {
    /// Для сайтов, которые открываются напрямую.
    local: String,
    /// DoH внутри туннеля для всего остального.
    remote: String,
}

impl Default for DnsChoice {
    fn default() -> Self {
        Self {
            local: "yandex".into(),
            remote: "cloudflare".into(),
        }
    }
}

fn load_choice(app: &AppHandle) -> settings::Loaded {
    match app.path().app_config_dir() {
        Ok(dir) => settings::load(&dir),
        Err(_) => settings::Loaded {
            choice: Choice::default(),
            notice: None,
        },
    }
}

fn save_choice(app: &AppHandle, choice: &Choice) -> Result<(), String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|_| "Не найдена папка настроек Windows — настройки не сохранились.")?;
    settings::save(&dir, choice)
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            store: Mutex::default(),
            servers: Mutex::default(),
            governor: Mutex::new(NetGovernor::new(NetPolicy::default())),
            migration: Mutex::default(),
            groups: Mutex::default(),
            checking: Default::default(),
            choice: Mutex::default(),
            outcomes: Mutex::default(),
            dns_report: Mutex::default(),
            health: health::client(),
            network: Mutex::default(),
            zapret_picking: Default::default(),
            zapret_cancel: Default::default(),
            zapret_last: Mutex::default(),
            zapret_release: Mutex::default(),
            zapret_wake: tokio::sync::Notify::new(),
            notices: Mutex::default(),
            tunnel: Mutex::default(),
            watchdog_wake: tokio::sync::Notify::new(),
            last_diagnosis: Mutex::default(),
            diag_files: Mutex::default(),
            session: Mutex::default(),
            pending_page: Mutex::default(),
            epoch: Default::default(),
        }
    }
}

impl AppState {
    fn entry(&self, key: &str) -> Option<catalog::Entry> {
        self.servers
            .lock()
            .ok()?
            .iter()
            .find(|e| e.key == key)
            .cloned()
    }

    /// Выбранный сервер; `None` — не выбран или его больше нет в подписках.
    fn selected(&self) -> Option<catalog::Entry> {
        let key = self.choice.lock().ok()?.server.clone()?;
        self.entry(&key)
    }

    /// Пользователь подключил, отключил или сменил сервер и режим. Автопереключение
    /// и переподключение после сна, начатые раньше, после этого ничего не делают:
    /// иначе «Отключить» во время проверки туннеля через полминуты включило бы VPN снова.
    pub(crate) fn user_acted(&self) {
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Название сервера для трея и уведомлений, где флаг картинкой не нарисовать:
/// без флагов-эмодзи (Windows показывает их буквами). У цепочки страны остаются
/// кодами — «EE для wifi · через RU», иначе одинаковые названия не различить.
pub(crate) fn display_name(s: &Server) -> String {
    let f = kvt_core::flag::split_flags(&s.name);
    match (f.flag, f.via) {
        (Some(exit), Some(via)) => format!(
            "{} {} · через {}",
            exit.to_uppercase(),
            f.name,
            via.to_uppercase()
        ),
        (None, Some(via)) => format!("{} · через {}", f.name, via.to_uppercase()),
        _ => f.name,
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerSummary {
    key: String,
    name: String,
    /// Страна выхода: код из флага в названии (`nl`).
    flag: Option<String>,
    /// Страна входа у цепочки серверов (`ru`).
    via: Option<String>,
    address: String,
    port: u16,
    protocol: &'static str,
    transport: &'static str,
    security: &'static str,
    sni: Option<String>,
    core: CoreKind,
}

impl ServerSummary {
    fn new(s: &Server, key: &str) -> Self {
        let transport = catalog::transport_kind(&s.transport);
        let security = match &s.security {
            Security::None => "none",
            Security::Tls(_) => "tls",
            Security::Reality(_) => "reality",
        };
        let f = kvt_core::flag::split_flags(&s.name);
        Self {
            key: key.to_owned(),
            name: f.name,
            flag: f.flag,
            via: f.via,
            address: s.address.clone(),
            port: s.port,
            protocol: s.protocol.kind(),
            transport,
            security,
            sni: s.visible_sni().map(str::to_owned),
            core: select_core(s).core,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionInfo {
    title: Option<String>,
    used_bytes: Option<u64>,
    total_bytes: Option<u64>,
    /// Unix-время окончания.
    expire: Option<u64>,
    support_url: Option<String>,
    announce: Option<String>,
}

impl From<&SubscriptionMeta> for SubscriptionInfo {
    fn from(m: &SubscriptionMeta) -> Self {
        Self {
            title: m.title.clone(),
            used_bytes: m.used_bytes(),
            total_bytes: m.total,
            expire: m.expire,
            support_url: m.support_url.clone(),
            announce: m.announce.clone(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    groups: Vec<catalog::Group>,
    choice: Choice,
}

/// Состояние для интерфейса, открытого заново из трея.
#[tauri::command]
fn snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    Ok(Snapshot {
        groups: state.groups.lock().map_err(crate::errors::state)?.clone(),
        choice: state.choice.lock().map_err(crate::errors::state)?.clone(),
    })
}

/// Интерфейс сообщает выбор сервера, режима, kill switch и маршрутизации.
#[tauri::command]
fn set_choice(
    mut choice: Choice,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    {
        let old = state.choice.lock().map_err(crate::errors::state)?;
        choice.recent = old.recent.clone();
        choice.autostart_offered = old.autostart_offered;
        if let Some(key) = choice
            .server
            .clone()
            .filter(|k| old.server.as_ref() != Some(k))
        {
            choice.remember(&key);
        }
    }
    save_choice(&app, &choice)?;
    *state.choice.lock().map_err(crate::errors::state)? = choice;
    tray::invalidate(&app);
    Ok(())
}

/// Резолверы для настроек DNS.
#[tauri::command]
fn dns_catalog() -> &'static [kvt_core::dns::Resolver] {
    kvt_core::dns::RESOLVERS
}

/// Списки itdoginfo (podkop) для раздела «Маршрутизация».
#[tauri::command]
fn list_catalog() -> &'static [kvt_core::lists::ListInfo] {
    kvt_core::lists::ITDOG_LISTS
}

/// Серверы одной подписки (`group`) или всех: ключи и серверы.
fn servers_of(state: &AppState, group: Option<&str>) -> Result<(Vec<String>, Vec<Server>), String> {
    Ok(state
        .servers
        .lock()
        .map_err(crate::errors::state)?
        .iter()
        .filter(|e| group.map_or(true, |g| e.sub == g))
        .map(|e| (e.key.clone(), e.server.clone()))
        .unzip())
}

/// Быстрая проверка (TCP-пинг без TLS): безопасна для ТСПУ, идёт параллельно.
/// Результат — по ключам серверов.
#[tauri::command]
async fn quick_check(
    group: Option<String>,
    state: State<'_, AppState>,
) -> Result<HashMap<String, QuickResult>, String> {
    let (keys, servers) = servers_of(&state, group.as_deref())?;
    let results = ping_servers(&servers).await?;
    Ok(keys.into_iter().zip(results).collect())
}

/// TCP-пинг серверов мимо туннеля. С VPN соединение из приложения принял бы сам
/// TUN (за 0 мс, и любой сервер выглядел бы рабочим) — тогда пингует служба,
/// напрямую через физический адаптер.
pub(crate) async fn ping_servers(servers: &[Server]) -> Result<Vec<QuickResult>, String> {
    if !matches!(
        query_status().await,
        Ok(Some(
            ServiceStatus::Connected { .. } | ServiceStatus::Connecting
        ))
    ) {
        return Ok(tester::quick_check(servers, Duration::from_secs(3), 8).await);
    }
    let targets = servers
        .iter()
        .map(|s| {
            (!matches!(s.protocol, Protocol::Hysteria2 { .. })).then(|| ipc::PingTarget {
                host: s.address.clone(),
                port: s.port,
            })
        })
        .collect();
    match service_client::call(Request::Ping { targets }).await {
        Ok(Response::Ping { results }) if results.len() == servers.len() => Ok(results),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err(crate::errors::UNEXPECTED.into()),
        Err(e) => Err(e),
    }
}

/// Строит план подключения по текущему выбору и отправляет его службе.
/// Конфиг ядра собирает служба. `verify` — после подключения проверить в фоне,
/// что через туннель идут данные (автопереключение проверяет само).
async fn connect_current(app: &AppHandle, verify: bool) -> Result<ServiceStatus, String> {
    let state = app.state::<AppState>();
    tunnel::set(app, None);
    let status = send_plan(&state).await?;
    if verify && matches!(status, ServiceStatus::Connected { .. }) {
        tunnel::spawn_verify(app.clone());
    }
    Ok(status)
}

/// Что отправить службе для текущего выбора.
pub(crate) enum Plan {
    Vpn(Box<ConnectPlan>),
    /// Только zapret: сервер не нужен, winws работает на всех интерфейсах.
    Zapret(kvt_core::ipc::ZapretPlan),
}

/// Подключение к выбранному серверу (или только zapret).
async fn send_plan(state: &AppState) -> Result<ServiceStatus, String> {
    let request = match build_plan(state)? {
        Plan::Vpn(plan) => Request::Connect(plan),
        Plan::Zapret(plan) => Request::StartZapret(Box::new(plan)),
    };
    match service_client::call(request).await? {
        Response::Status { status, session } => {
            if let Ok(mut s) = state.session.lock() {
                *s = session;
            }
            Ok(status)
        }
        Response::Error { message } => Err(message),
        _ => Err(crate::errors::UNEXPECTED.into()),
    }
}

/// План по текущему выбору. Конфиг ядра из него собирает служба (а для
/// экспорта диагностики — приложение тем же компилятором).
pub(crate) fn build_plan(state: &AppState) -> Result<Plan, String> {
    let choice = state.choice.lock().map_err(crate::errors::state)?.clone();
    let mode = choice.mode.unwrap_or_else(|| "vpn".into());
    let network = zapret::network_key(state);
    if mode == "zapret" {
        return Ok(Plan::Zapret(choice.zapret.plan(network.as_deref())));
    }
    let server = state
        .selected()
        .ok_or("Выберите сервер в списке на главной.")?
        .server;

    let mut routing = presets::from_settings(&choice.routing)
        .with_servers([server.address.clone()])
        .with_health_check()
        .with_update_hosts();
    if mode == "hybrid" {
        routing.extend(presets::zapret_youtube_discord());
    }
    routing.validate().map_err(|e| {
        errors::logged(
            "Настройки маршрутизации противоречат друг другу — проверьте раздел «Маршрутизация».",
            e,
        )
    })?;
    let plan = ConnectPlan {
        core: select_core(&server).core,
        server,
        routing,
        kill_switch: choice.kill_switch,
        dns: DnsPlan::from_ids(&choice.dns.local, &choice.dns.remote).map_err(|e| {
            errors::logged(
                "Выбранный DNS-сервер больше не поддерживается — выберите другой в настройках.",
                e,
            )
        })?,
        // Гибрид: winws рядом с ядром, домены zapret служба берёт из RoutingPlan.
        zapret: (mode == "hybrid").then(|| choice.zapret.plan(network.as_deref())),
    };
    Ok(Plan::Vpn(Box::new(plan)))
}

#[tauri::command]
async fn connect(app: AppHandle) -> Result<ServiceStatus, String> {
    app.state::<AppState>().user_acted();
    let result = connect_current(&app, true).await;
    tray::refresh(&app).await;
    result
}

/// Сообщения, которые появились до открытия окна (окно забирает их один раз).
#[tauri::command]
fn take_notices(state: State<'_, AppState>) -> Vec<String> {
    state
        .notices
        .lock()
        .map(|mut n| std::mem::take(&mut *n))
        .unwrap_or_default()
}

/// Проверка утечек: открытые прокси на этом компьютере, маршруты и DNS.
#[tauri::command]
async fn leak_test(connected: bool) -> diagnostics::LeakReport {
    diagnostics::run(connected).await
}

async fn disconnect_service() -> Result<ServiceStatus, String> {
    match service_client::call(Request::Disconnect).await? {
        Response::Ok => Ok(ServiceStatus::Disconnected),
        Response::Error { message } => Err(message),
        _ => Err(crate::errors::UNEXPECTED.into()),
    }
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Result<ServiceStatus, String> {
    app.state::<AppState>().user_acted();
    let result = disconnect_service().await;
    tray::refresh(&app).await;
    result
}

/// Статус службы. Если служба не запущена — `None` и текст причины не нужен:
/// интерфейс просто показывает «Отключено».
#[tauri::command]
async fn service_status() -> Result<Option<ServiceStatus>, String> {
    query_status().await
}

/// Время и трафик текущего сеанса из последнего ответа службы (без запроса к ней).
#[tauri::command]
fn service_session(state: State<'_, AppState>) -> Option<Session> {
    state.session.lock().ok().and_then(|s| *s)
}

async fn query_status() -> Result<Option<ServiceStatus>, String> {
    let (result, session) = match service_client::call(Request::Status).await {
        Ok(Response::Status { status, session }) => (Ok(Some(status)), session),
        Ok(Response::Error { message }) => (Err(message), None),
        Ok(_) => (Err(crate::errors::UNEXPECTED.into()), None),
        Err(_) => (Ok(None), None),
    };
    if let Some(app) = APP.get() {
        if let Ok(mut s) = app.state::<AppState>().session.lock() {
            *s = session;
        }
    }
    result
}

/// Для мест без `AppHandle` под рукой (статус службы спрашивают отовсюду).
static APP: std::sync::OnceLock<AppHandle> = std::sync::OnceLock::new();

/// Первый запуск установленного KVT включает автозапуск («включён после установки»).
/// Установщик этого не делает: он работает от администратора, и `HKCU` у него может
/// оказаться чужим. Сборка для разработки автозапуск не трогает.
fn enable_autostart_once(app: &AppHandle) {
    if !autostart::installed() {
        return;
    }
    let state = app.state::<AppState>();
    let Ok(mut choice) = state.choice.lock() else {
        return;
    };
    if choice.autostart_offered {
        return;
    }
    if let Err(e) = autostart::set_autostart(true) {
        tracing::warn!(error = %e, "автозапуск не включился");
        return;
    }
    choice.autostart_offered = true;
    let _ = save_choice(app, &choice);
}

/// Сколько ждать службу после запуска KVT. Служба стоит в отложенном автозапуске:
/// Windows запускает её примерно через 2 минуты после загрузки, а KVT из автозагрузки
/// стартует раньше. Поэтому KVT запускает службу сам (это разрешено пользователю),
/// а если не вышло — ждёт с запасом.
const SERVICE_WAIT: Duration = Duration::from_secs(5 * 60);

/// Ждёт, пока служба начнёт отвечать. Если её нет — один раз просит Windows её
/// запустить. `Err` — служба так и не ответила (текст для пользователя).
pub(crate) async fn wait_for_service() -> Result<ServiceStatus, String> {
    let start = Instant::now();
    let mut asked = false;
    loop {
        if let Ok(Some(status)) = query_status().await {
            return Ok(status);
        }
        if service_client::version_mismatch() {
            return Err(errors::VERSION_MISMATCH.into());
        }
        if !asked {
            asked = true;
            match tauri::async_runtime::spawn_blocking(about::start_blocking).await {
                Ok(Ok(())) => tracing::info!("служба KVT запущена из приложения"),
                // Не установлена или отключена — ждать бесполезно.
                Ok(Err(message)) => return Err(message),
                Err(_) => {}
            }
        }
        if start.elapsed() >= SERVICE_WAIT {
            return Err(errors::NO_SERVICE.into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// «Подключаться при запуске»: ждёт службу (после загрузки Windows она
/// стартует не сразу) и подключается, если ничего ещё не работает.
fn spawn_connect_on_start(app: AppHandle) {
    let enabled = app
        .state::<AppState>()
        .choice
        .lock()
        .map(|c| c.connect_on_start)
        .unwrap_or(false);
    if !enabled {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let epoch = app.state::<AppState>().epoch();
        let result = match wait_for_service().await {
            // Пока ждали, пользователь сам подключился или отключился.
            Ok(_) if app.state::<AppState>().epoch() != epoch => return,
            Ok(ServiceStatus::Disconnected | ServiceStatus::Failed { .. }) => {
                connect_current(&app, true).await.map(|_| ())
            }
            // Уже подключено (профиль сети) или идёт подключение.
            Ok(_) => return,
            Err(message) => Err(message),
        };
        if let Err(message) = result {
            notify::error(
                &app,
                &format!("Не удалось подключиться при запуске: {message}"),
            );
        }
        tray::invalidate(&app);
    });
}

/// Выбор из прежних версий: номер сервера в «основной» подписке (до единого списка)
/// и ключи до 0.9.2 (с параметрами TLS) → нынешние ключи.
fn migrate_choice(app: &AppHandle, state: &AppState) {
    let (active, legacy) = {
        let Ok(store) = state.store.lock() else {
            return;
        };
        let Some(store) = store.as_ref() else {
            return;
        };
        let entries = state.servers.lock().map(|s| s.clone()).unwrap_or_default();
        (store.active.clone(), catalog::legacy_keys(store, &entries))
    };
    let Ok(mut choice) = state.choice.lock() else {
        return;
    };
    let known = |key: &String| state.entry(key).is_some();
    let mut changed = false;
    if let Some(new) = choice
        .server
        .as_ref()
        .filter(|k| !known(k))
        .and_then(|k| legacy.get(k))
    {
        choice.server = Some(new.clone());
        changed = true;
    }
    for key in &mut choice.recent {
        if let Some(new) = legacy.get(key).filter(|_| !known(key)) {
            *key = new.clone();
            changed = true;
        }
    }
    let Some(index) = choice.server_index.take() else {
        if changed {
            let _ = save_choice(app, &choice);
        }
        return;
    };
    if choice.server.is_none() {
        choice.server = state.servers.lock().ok().and_then(|servers| {
            servers
                .iter()
                .filter(|e| Some(&e.sub) == active.as_ref())
                .nth(usize::try_from(index).ok()?)
                .map(|e| e.key.clone())
        });
    }
    let _ = save_choice(app, &choice);
}

fn main() {
    let app = tauri::Builder::default()
        // Должен регистрироваться первым: второй экземпляр завершится раньше,
        // чем попытается занять папку данных WebView2.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::show_main_window(app);
        }))
        .manage(AppState::default())
        .setup(|app| {
            let _ = APP.set(app.handle().clone());
            if let Ok(dir) = app.path().app_local_data_dir() {
                applog::init(&dir.join("logs"));
            }
            let loaded = load_choice(app.handle());
            let state = app.state::<AppState>();
            if let Ok(mut c) = state.choice.lock() {
                *c = loaded.choice;
            }
            if let (Some(notice), Ok(mut n)) = (loaded.notice, state.notices.lock()) {
                n.push(notice);
            }
            let store = subs::load(app.handle())?;
            if let Ok(mut s) = state.store.lock() {
                *s = Some(store);
            }
            subs::rebuild(&state)?;
            migrate_choice(app.handle(), &state);
            subs::spawn_updater(app.handle().clone());
            tray::create(app.handle())?;
            notify::spawn(app.handle());
            updates::spawn(app.handle().clone());
            // Автозапуск (`--tray`) — сразу в трей; обычный запуск открывает окно.
            if !autostart::started_in_tray() {
                tray::show_main_window(app.handle());
            }
            spawn_connect_on_start(app.handle().clone());
            enable_autostart_once(app.handle());
            netprofile::spawn(app.handle().clone());
            watchdog::spawn(app.handle().clone());
            zapret::spawn_watch(app.handle().clone());
            power::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            subs::parse_subscription,
            subs::add_subscription_url,
            subs::list_subscriptions,
            subs::remove_subscription,
            subs::remove_server,
            subs::refresh_subscription,
            quick_check,
            prober::full_check,
            connect,
            disconnect,
            service_status,
            service_session,
            leak_test,
            snapshot,
            set_choice,
            list_catalog,
            dns_catalog,
            dnscheck::dns_check,
            troubleshoot::troubleshoot,
            netprofile::current_network,
            zapret::zapret_strategies,
            zapret::zapret_conflicts,
            zapret::zapret_stop_conflicts,
            zapret::zapret_autoselect,
            zapret::zapret_autoselect_cancel,
            zapret::zapret_info,
            zapret::zapret_latest,
            zapret::zapret_update,
            zapret::zapret_repair,
            zapret::zapret_check,
            zapret::zapret_last,
            zapret::zapret_diagnose,
            journal::net_log,
            journal::net_log_clear,
            audit::pc_audit,
            audit::pc_audit_fix,
            migrate::migrate_scan,
            migrate::migrate_pick_folder,
            migrate::migrate_import,
            take_notices,
            tray::take_page,
            autostart::autostart_enabled,
            autostart::set_autostart,
            about::about_info,
            about::open_link,
            updates::update_status,
            updates::update_check,
            about::start_service,
            service_client::service_mismatch,
            tunnel::tunnel_state,
            diagexport::diag_preview,
            diagexport::diag_save
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "KVT не смог запуститься");
            eprintln!("KVT не смог запуститься: {e}");
            std::process::exit(1);
        });
    app.run(|_app, event| {
        // Закрытие окна не завершает KVT: окно вместе с WebView уничтожается,
        // а приложение остаётся в трее. Выход — пунктом «Выход» в меню трея.
        if let tauri::RunEvent::ExitRequested {
            api, code: None, ..
        } = event
        {
            api.prevent_exit();
        }
    });
}
