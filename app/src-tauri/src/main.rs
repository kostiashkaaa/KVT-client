// Без консольного окна в релизной сборке.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod diagnostics;
mod dpapi;
mod fetch;
mod prober;
mod service_client;
mod store;
mod subs;
mod tray;

use kvt_core::core_select::{select_core, CoreKind};
use kvt_core::governor::{NetGovernor, NetPolicy};
use kvt_core::ipc::{ConnectPlan, Request, Response, ServiceStatus};
use kvt_core::model::{FingerprintAdvice, Security, Server, Transport};
use kvt_core::routing::presets::{self, RoutingSettings};
use kvt_core::subscription::SubscriptionMeta;
use kvt_core::tester::{self, QuickResult};
use serde::Serialize;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Manager, State};

/// Подписки, серверы и ключи живут в Rust; в WebView уходит только
/// `ServerSummary` без паролей, UUID и токенов.
pub(crate) struct AppState {
    /// Сохранённые подписки (загружаются при старте из каталога данных).
    store: Mutex<Option<store::Store>>,
    /// Серверы активной подписки.
    servers: Mutex<Vec<Server>>,
    governor: Mutex<NetGovernor>,
    /// Активная подписка в виде для интерфейса: окно может быть закрыто
    /// (WebView выгружен), а при открытии интерфейс восстанавливается отсюда.
    last: Mutex<Option<ParsedSubscription>>,
    /// Идёт полная проверка серверов (одновременно — только одна).
    checking: std::sync::atomic::AtomicBool,
    /// Выбранный сервер, режим и kill switch — ими пользуется и трей.
    choice: Mutex<Choice>,
}

/// Выбор пользователя. Секретов не содержит, поэтому хранится в settings.json
/// в каталоге настроек приложения.
#[derive(Clone, Default, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Choice {
    server_index: Option<i64>,
    mode: Option<String>,
    kill_switch: bool,
    routing: RoutingSettings,
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
            last: Mutex::default(),
            checking: Default::default(),
            choice: Mutex::default(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerSummary {
    name: String,
    address: String,
    port: u16,
    protocol: &'static str,
    transport: &'static str,
    security: &'static str,
    sni: Option<String>,
    core: CoreKind,
    fingerprint_advice: Option<FingerprintAdvice>,
}

impl From<&Server> for ServerSummary {
    fn from(s: &Server) -> Self {
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
        Self {
            name: s.name.clone(),
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

#[derive(Clone, Serialize)]
pub(crate) struct LineError {
    line: usize,
    message: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct ParsedSubscription {
    id: Option<String>,
    servers: Vec<ServerSummary>,
    info: Vec<String>,
    errors: Vec<LineError>,
    duplicates: usize,
    meta: Option<SubscriptionInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    subscription: Option<ParsedSubscription>,
    choice: Choice,
}

/// Состояние для интерфейса, открытого заново из трея.
#[tauri::command]
fn snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    Ok(Snapshot {
        subscription: state
            .last
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

/// Списки itdoginfo (podkop) для раздела «Маршрутизация».
#[tauri::command]
fn list_catalog() -> &'static [kvt_core::lists::ListInfo] {
    kvt_core::lists::ITDOG_LISTS
}

/// Быстрая проверка (TCP-пинг без TLS): безопасна для ТСПУ, идёт параллельно.
#[tauri::command]
async fn quick_check(state: State<'_, AppState>) -> Result<Vec<QuickResult>, String> {
    let servers = state
        .servers
        .lock()
        .map_err(|_| "внутренняя ошибка состояния")?
        .clone();
    Ok(tester::quick_check(&servers, Duration::from_secs(3), 8).await)
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
    if mode == "zapret" {
        return Err("Режим zapret появится на этапе 4.".into());
    }
    let server = {
        let servers = state
            .servers
            .lock()
            .map_err(|_| "внутренняя ошибка состояния")?;
        choice
            .server_index
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| servers.get(i))
            .cloned()
            .ok_or("Выберите сервер")?
    };

    let mut routing =
        presets::from_settings(&choice.routing).with_servers([server.address.clone()]);
    if mode == "hybrid" {
        routing.extend(presets::zapret_youtube_discord());
    }
    routing.validate().map_err(|e| e.to_string())?;
    let plan = ConnectPlan {
        core: select_core(&server).core,
        server,
        routing,
        kill_switch: choice.kill_switch,
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
            subs::activate(&state)?;
            subs::spawn_updater(app.handle().clone());
            tray::create(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            subs::parse_subscription,
            subs::add_subscription_url,
            subs::list_subscriptions,
            subs::select_subscription,
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
            list_catalog
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
