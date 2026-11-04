// Без консольного окна в релизной сборке.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod audit;
mod catalog;
mod diagnostics;
mod dnscheck;
mod dpapi;
mod fetch;
mod health;
mod journal;
mod netinfo;
mod netprofile;
mod prober;
mod service_client;
mod store;
mod subs;
mod tray;
mod troubleshoot;
mod watchdog;
mod zapret;

use kvt_core::compile::DnsPlan;
use kvt_core::core_select::{select_core, CoreKind};
use kvt_core::governor::{NetGovernor, NetPolicy};
use kvt_core::ipc::{ConnectPlan, Request, Response, ServiceStatus};
use kvt_core::model::{FingerprintAdvice, Security, Server, Transport};
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

const SETTINGS_FILE: &str = "settings.json";

fn load_choice(app: &AppHandle) -> Choice {
    app.path()
        .app_config_dir()
        .ok()
        .and_then(|dir| std::fs::read(dir.join(SETTINGS_FILE)).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_choice(app: &AppHandle, choice: &Choice) -> Result<(), String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(choice).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("{SETTINGS_FILE}.tmp"));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(tmp, dir.join(SETTINGS_FILE)).map_err(|e| e.to_string())
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            store: Mutex::default(),
            servers: Mutex::default(),
            governor: Mutex::new(NetGovernor::new(NetPolicy::default())),
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
}

/// Название сервера без флага-эмодзи (флаг интерфейс рисует картинкой).
pub(crate) fn display_name(s: &Server) -> String {
    kvt_core::flag::split_flag(&s.name).1
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerSummary {
    key: String,
    name: String,
    /// Код страны из флага в названии (`nl`).
    flag: Option<String>,
    address: String,
    port: u16,
    protocol: &'static str,
    transport: &'static str,
    security: &'static str,
    sni: Option<String>,
    core: CoreKind,
    fingerprint_advice: Option<FingerprintAdvice>,
}

impl ServerSummary {
    fn new(s: &Server, key: &str) -> Self {
        let transport = match s.transport {
            Transport::Tcp => "tcp",
            Transport::Ws { .. } => "ws",
            Transport::Grpc { .. } => "grpc",
            Transport::HttpUpgrade { .. } => "httpupgrade",
            Transport::Xhttp { .. } => "xhttp",
            Transport::Quic => "quic",
        };
        let (security, fingerprint) = match &s.security {
            Security::None => ("none", None),
            Security::Tls(t) => ("tls", t.fingerprint),
            Security::Reality(r) => ("reality", Some(r.fingerprint)),
        };
        let (flag, name) = kvt_core::flag::split_flag(&s.name);
        Self {
            key: key.to_owned(),
            name,
            flag,
            address: s.address.clone(),
            port: s.port,
            protocol: s.protocol.kind(),
            transport,
            security,
            sni: s.visible_sni().map(str::to_owned),
            core: select_core(s).core,
            fingerprint_advice: fingerprint.map(|f| f.advice()),
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
        groups: state
            .groups
            .lock()
            .map_err(|_| "внутренняя ошибка состояния")?
            .clone(),
        choice: state
            .choice
            .lock()
            .map_err(|_| "внутренняя ошибка состояния")?
            .clone(),
    })
}

/// Интерфейс сообщает выбор сервера, режима, kill switch и маршрутизации.
#[tauri::command]
fn set_choice(choice: Choice, app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    save_choice(&app, &choice)?;
    *state
        .choice
        .lock()
        .map_err(|_| "внутренняя ошибка состояния")? = choice;
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
        .map_err(|_| "внутренняя ошибка состояния")?
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
    let results = tester::quick_check(&servers, Duration::from_secs(3), 8).await;
    Ok(keys.into_iter().zip(results).collect())
}

/// Строит план подключения по текущему выбору и отправляет его службе.
/// Конфиг ядра собирает служба.
async fn connect_current(state: &AppState) -> Result<ServiceStatus, String> {
    let choice = state
        .choice
        .lock()
        .map_err(|_| "внутренняя ошибка состояния")?
        .clone();
    let mode = choice.mode.unwrap_or_else(|| "vpn".into());
    let network = zapret::network_key(state);
    if mode == "zapret" {
        // Только zapret: сервер не нужен, winws работает на всех интерфейсах.
        let plan = choice.zapret.plan(network.as_deref());
        return match service_client::call(Request::StartZapret(Box::new(plan))).await? {
            Response::Status { status } => Ok(status),
            Response::Error { message } => Err(message),
            _ => Err("Неожиданный ответ службы".into()),
        };
    }
    let server = state.selected().ok_or("Выберите сервер")?.server;

    let mut routing = presets::from_settings(&choice.routing)
        .with_servers([server.address.clone()])
        .with_health_check();
    if mode == "hybrid" {
        routing.extend(presets::zapret_youtube_discord());
    }
    routing.validate().map_err(|e| e.to_string())?;
    let plan = ConnectPlan {
        core: select_core(&server).core,
        server,
        routing,
        kill_switch: choice.kill_switch,
        dns: DnsPlan::from_ids(&choice.dns.local, &choice.dns.remote).map_err(|e| e.to_string())?,
        // Гибрид: winws рядом с ядром, домены zapret служба берёт из RoutingPlan.
        zapret: (mode == "hybrid").then(|| choice.zapret.plan(network.as_deref())),
    };
    match service_client::call(Request::Connect(Box::new(plan))).await? {
        Response::Status { status } => Ok(status),
        Response::Error { message } => Err(message),
        _ => Err("Неожиданный ответ службы".into()),
    }
}

#[tauri::command]
async fn connect(app: AppHandle, state: State<'_, AppState>) -> Result<ServiceStatus, String> {
    let result = connect_current(&state).await;
    tray::refresh(&app).await;
    result
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
        _ => Err("Неожиданный ответ службы".into()),
    }
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Result<ServiceStatus, String> {
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

async fn query_status() -> Result<Option<ServiceStatus>, String> {
    match service_client::call(Request::Status).await {
        Ok(Response::Status { status }) => Ok(Some(status)),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("Неожиданный ответ службы".into()),
        Err(_) => Ok(None),
    }
}

/// Выбор из версий до единого списка: номер сервера в «основной» подписке → ключ.
fn migrate_choice(app: &AppHandle, state: &AppState) {
    let active = state
        .store
        .lock()
        .ok()
        .and_then(|s| s.as_ref()?.active.clone());
    let Ok(mut choice) = state.choice.lock() else {
        return;
    };
    let Some(index) = choice.server_index.take() else {
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
            let choice = load_choice(app.handle());
            let state = app.state::<AppState>();
            if let Ok(mut c) = state.choice.lock() {
                *c = choice;
            }
            let store = subs::load(app.handle())?;
            if let Ok(mut s) = state.store.lock() {
                *s = Some(store);
            }
            subs::rebuild(&state)?;
            migrate_choice(app.handle(), &state);
            subs::spawn_updater(app.handle().clone());
            tray::create(app.handle())?;
            netprofile::spawn(app.handle().clone());
            watchdog::spawn(app.handle().clone());
            zapret::spawn_watch(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            subs::parse_subscription,
            subs::add_subscription_url,
            subs::list_subscriptions,
            subs::remove_subscription,
            subs::refresh_subscription,
            quick_check,
            prober::full_check,
            connect,
            disconnect,
            service_status,
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
            audit::pc_audit_fix
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
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
