//! zapret в приложении: выбор стратегии, проверка, автоподбор, диагностика и
//! обслуживание комплекта.
//!
//! Стратегии, конфликты и комплект знает служба (он лежит рядом с ней). Проверка
//! идёт отсюда: служба запускает winws, а приложение проверяет цели Flowseal
//! (Discord, YouTube) обычными запросами — TLS 1.2 и TLS 1.3, как
//! `test zapret.ps1`, плюс загрузку больше 32 КБ, чтобы поймать заморозку после
//! первых 16–20 КБ. Цели — публичные сервисы, а не VPN-серверы, поэтому
//! NetGovernor здесь не нужен: столько же соединений открывает одна вкладка YouTube.

use crate::troubleshoot::{Step, StepState, Tone};
use crate::{connect_current, query_status, save_choice, service_client, watchdog, AppState};
use kvt_core::ipc::{
    Conflict, MaintenanceReport, Request, Response, ServiceStatus, ZapretInfo, ZapretPlan,
};
use kvt_core::zapret::{GameFilter, Release, Strategy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::windows::process::CommandExt as _;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

/// Стратегия по умолчанию — основная у Flowseal.
pub const DEFAULT_STRATEGY: &str = "general";
pub const PROGRESS_EVENT: &str = "zapret-progress";
/// Итог проверки (ручной или автоматической).
pub const CHECK_EVENT: &str = "zapret-check";
/// Автопроверка что-то сделала сама или требует внимания.
pub const AUTO_EVENT: &str = "zapret-auto";

const TARGETS: &[(&str, &str)] = &[
    ("Discord", "https://discord.com/"),
    ("Discord: подключение", "https://gateway.discord.gg/"),
    ("Discord: файлы", "https://cdn.discordapp.com/"),
    ("YouTube", "https://www.youtube.com/"),
    ("YouTube: картинки", "https://i.ytimg.com/"),
    ("YouTube: видео", "https://redirector.googlevideo.com/"),
];
/// Картинка YouTube больше 32 КБ: если поток встаёт на 16–20 КБ — это заморозка DPI.
const DOWNLOAD: &str = "https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg";
const DOWNLOAD_ENOUGH: u64 = 32 * 1024;
const TIMEOUT: Duration = Duration::from_secs(6);
const STALL: Duration = Duration::from_secs(4);
/// Две проверки на цель (TLS 1.3 и TLS 1.2) и одна загрузка.
pub const MAX_SCORE: u32 = TARGETS.len() as u32 * 2 + 1;
/// Сколько проверок можно провалить и считать, что всё работает (одна цель капризничает).
const TOLERANCE: u32 = 2;
/// Автопроверка: раз в полчаса и после смены сети.
const WATCH_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Ответ GitHub о последнем релизе живёт столько.
const RELEASE_CACHE: Duration = Duration::from_secs(6 * 3600);

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ZapretChoice {
    /// Выбранная вручную стратегия; `None` — основная.
    pub strategy: Option<String>,
    pub game_filter: GameFilter,
    /// Разрешить включать TCP timestamps для стратегий с `fooling=ts`.
    pub tcp_timestamps: bool,
    /// Итог автоподбора для каждой сети (ключ сети → стратегия).
    pub by_network: HashMap<String, String>,
    /// Обход по IP-списку Flowseal, а не только по доменам.
    pub ipset: bool,
    /// Проверять работу раз в полчаса и после смены сети.
    pub auto_check: bool,
    /// Если стратегия перестала работать — подобрать новую (в режиме «Zapret»).
    pub auto_pick: bool,
    /// Прокси для Telegram Desktop: работает, пока KVT подключён в любом режиме.
    pub telegram: bool,
    /// Путь прокси в «Гибриде»: сначала через VPN или всегда мимо него.
    pub telegram_route: kvt_core::tgproxy::Route,
}

impl Default for ZapretChoice {
    fn default() -> Self {
        Self {
            strategy: None,
            game_filter: GameFilter::Off,
            tcp_timestamps: true,
            by_network: HashMap::new(),
            ipset: false,
            auto_check: true,
            auto_pick: true,
            telegram: true,
            telegram_route: kvt_core::tgproxy::Route::default(),
        }
    }
}

impl ZapretChoice {
    /// Стратегия для сети: подобранная для неё, иначе выбранная, иначе основная.
    pub fn strategy_for(&self, network: Option<&str>) -> String {
        network
            .and_then(|k| self.by_network.get(k))
            .or(self.strategy.as_ref())
            .cloned()
            .unwrap_or_else(|| DEFAULT_STRATEGY.to_owned())
    }

    /// Только списки Flowseal, своих доменов нет: zapret помогает лишь там, где
    /// блокируют по имени сайта, а в «Гибриде» до него доходят только YouTube и Discord.
    pub fn plan(&self, network: Option<&str>) -> ZapretPlan {
        ZapretPlan {
            strategy: self.strategy_for(network),
            game_filter: self.game_filter,
            tcp_timestamps: self.tcp_timestamps,
            domains: Vec::new(),
            // winws не трогает соединения прокси Telegram: подделка пакетов их рвёт.
            exclude_domains: if self.telegram {
                crate::tgproxy::zapret_exclusions()
            } else {
                Vec::new()
            },
            ipset: self.ipset,
        }
    }
}

pub fn network_key(state: &AppState) -> Option<String> {
    state
        .network
        .lock()
        .ok()
        .and_then(|n| n.as_ref().map(|n| n.key.clone()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn call(request: Request) -> Result<Response, String> {
    match service_client::call(request).await? {
        Response::Error { message } => Err(message),
        other => Ok(other),
    }
}

const UNEXPECTED: &str = crate::errors::UNEXPECTED;

#[tauri::command]
pub async fn zapret_strategies() -> Result<Vec<Strategy>, String> {
    match call(Request::ZapretStrategies).await? {
        Response::Strategies { strategies } => Ok(strategies),
        _ => Err(UNEXPECTED.into()),
    }
}

#[tauri::command]
pub async fn zapret_conflicts() -> Result<Vec<Conflict>, String> {
    match call(Request::ZapretConflicts).await? {
        Response::Conflicts { conflicts } => Ok(conflicts),
        _ => Err(UNEXPECTED.into()),
    }
}

/// Остановить чужие обходы — только по кнопке пользователя.
#[tauri::command]
pub async fn zapret_stop_conflicts() -> Result<Vec<Conflict>, String> {
    match call(Request::StopConflicts).await? {
        Response::Conflicts { conflicts } => Ok(conflicts),
        _ => Err(UNEXPECTED.into()),
    }
}

#[tauri::command]
pub async fn zapret_info() -> Result<ZapretInfo, String> {
    match call(Request::ZapretInfo).await? {
        Response::ZapretInfo(info) => Ok(*info),
        _ => Err(UNEXPECTED.into()),
    }
}

/// Последний релиз Flowseal (один запрос к API GitHub, ответ живёт 6 часов).
#[tauri::command]
pub async fn zapret_latest(force: bool, state: State<'_, AppState>) -> Result<Release, String> {
    if !force {
        if let Some((at, release)) = state.zapret_release.lock().ok().and_then(|r| r.clone()) {
            if at.elapsed() < RELEASE_CACHE {
                return Ok(release);
            }
        }
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("KVT/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    let body = async {
        client
            .get(kvt_core::zapret::RELEASES_API)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?
            .bytes()
            .await
            .map_err(|e| e.without_url().to_string())
    }
    .await;
    {
        use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
        let outcome = if body.is_ok() {
            Outcome::Ok
        } else {
            Outcome::Failed
        };
        netlog::record(
            netlog::Event::new(
                Origin::App,
                Purpose::Update,
                &netlog::host_of(kvt_core::zapret::RELEASES_API),
                Route::Direct,
                outcome,
            )
            .ms(start.elapsed())
            .detail(
                body.as_ref()
                    .err()
                    .map_or("версия Flowseal", String::as_str),
            ),
        );
    }
    let body = body?;
    let release = kvt_core::zapret::parse_release(&body)?;
    if let Ok(mut cache) = state.zapret_release.lock() {
        *cache = Some((Instant::now(), release.clone()));
    }
    Ok(release)
}

/// Обновление и переустановка останавливают zapret — после них подключаемся как было.
async fn maintain(app: &AppHandle, request: Request) -> Result<MaintenanceReport, String> {
    let state = app.state::<AppState>();
    if state.zapret_picking.load(Ordering::SeqCst) {
        return Err("Идёт подбор стратегии — дождитесь его окончания".into());
    }
    let before = query_status().await?;
    let report = match call(request).await? {
        Response::Maintenance(report) => *report,
        _ => return Err(UNEXPECTED.into()),
    };
    // Обновлять было нечего — служба ничего не останавливала, VPN не рвём.
    if report.changed
        && matches!(
            before,
            Some(ServiceStatus::Connected { .. } | ServiceStatus::Zapret { .. })
        )
    {
        let _ = connect_current(app, true).await;
    }
    crate::tray::refresh(app).await;
    Ok(report)
}

#[tauri::command]
pub async fn zapret_update(app: AppHandle) -> Result<MaintenanceReport, String> {
    maintain(&app, Request::ZapretUpdate).await
}

#[tauri::command]
pub async fn zapret_repair(app: AppHandle) -> Result<MaintenanceReport, String> {
    maintain(&app, Request::ZapretRepair).await
}

// ── Проверка ──

fn client(tls12: bool) -> reqwest::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(4))
        // Каждая проверка — новое соединение: иначе проверялась бы прошлая стратегия.
        .pool_max_idle_per_host(0);
    if tls12 {
        b = b.max_tls_version(reqwest::tls::Version::TLS_1_2);
    }
    b.build()
}

/// Ответ пришёл (любой код HTTP) — значит, рукопожатие и запрос прошли DPI.
async fn reachable(client: &reqwest::Client, url: &str) -> Option<u64> {
    let start = Instant::now();
    let result = client.get(url).send().await;
    log_check(url, result.is_ok(), start, "");
    result.ok().map(|_| start.elapsed().as_millis() as u64)
}

fn log_check(url: &str, ok: bool, start: Instant, detail: &str) {
    use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
    let outcome = if ok { Outcome::Ok } else { Outcome::Failed };
    netlog::record(
        netlog::Event::new(
            Origin::App,
            Purpose::Zapret,
            &netlog::host_of(url),
            Route::Direct,
            outcome,
        )
        .ms(start.elapsed())
        .detail(detail),
    );
}

/// Загрузка проходит дальше окна заморозки (16–20 КБ).
async fn downloads(client: &reqwest::Client) -> bool {
    let start = Instant::now();
    let ok = download_passes(client).await;
    let detail = if ok {
        "загрузка прошла"
    } else {
        "загрузка оборвалась"
    };
    log_check(DOWNLOAD, ok, start, detail);
    ok
}

async fn download_passes(client: &reqwest::Client) -> bool {
    let Ok(mut response) = client.get(DOWNLOAD).send().await else {
        return false;
    };
    let mut bytes = 0u64;
    loop {
        match tokio::time::timeout(STALL, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                bytes += chunk.len() as u64;
                if bytes >= DOWNLOAD_ENOUGH {
                    return true;
                }
            }
            // Файл кончился раньше порога — значит, не обрывали.
            Ok(Ok(None)) => return bytes > 0,
            _ => return false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetCheck {
    pub name: &'static str,
    /// Задержка по TLS 1.3 и TLS 1.2; `None` — не открылось.
    pub tls13: Option<u64>,
    pub tls12: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub targets: Vec<TargetCheck>,
    /// Загрузка больше 32 КБ прошла без обрыва.
    pub download: bool,
    pub passed: u32,
    pub max: u32,
    /// Суммарная задержка успешных проверок — для выбора между равными.
    pub latency_ms: u64,
}

impl Check {
    fn better_than(&self, other: &Check) -> bool {
        (self.passed, std::cmp::Reverse(self.latency_ms))
            > (other.passed, std::cmp::Reverse(other.latency_ms))
    }

    pub fn healthy(&self) -> bool {
        self.passed + TOLERANCE >= self.max
    }
}

/// Все проверки параллельно: около 6 секунд.
pub async fn measure() -> Check {
    let (Ok(modern), Ok(tls12)) = (client(false), client(true)) else {
        return Check {
            targets: Vec::new(),
            download: false,
            passed: 0,
            max: MAX_SCORE,
            latency_ms: 0,
        };
    };
    let mut set = tokio::task::JoinSet::new();
    for (i, (_, url)) in TARGETS.iter().enumerate() {
        for (legacy, c) in [(false, modern.clone()), (true, tls12.clone())] {
            set.spawn(async move { (i, legacy, reachable(&c, url).await) });
        }
    }
    let download = tokio::spawn(async move { downloads(&modern).await });
    let mut targets: Vec<TargetCheck> = TARGETS
        .iter()
        .map(|(name, _)| TargetCheck {
            name,
            tls13: None,
            tls12: None,
        })
        .collect();
    while let Some(Ok((i, legacy, ms))) = set.join_next().await {
        if legacy {
            targets[i].tls12 = ms;
        } else {
            targets[i].tls13 = ms;
        }
    }
    let download = download.await.unwrap_or(false);
    let ok: Vec<u64> = targets
        .iter()
        .flat_map(|t| [t.tls13, t.tls12])
        .flatten()
        .collect();
    Check {
        passed: ok.len() as u32 + u32::from(download),
        latency_ms: ok.iter().sum(),
        targets,
        download,
        max: MAX_SCORE,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRecord {
    /// Unix-время проверки.
    pub at: u64,
    /// Стратегия во время проверки; `None` — zapret не работал.
    pub strategy: Option<String>,
    pub check: Check,
}

/// Стратегия, которая работает сейчас (в режиме «Zapret» или в гибриде).
async fn running_strategy(state: &AppState) -> Option<String> {
    match query_status().await.ok().flatten()? {
        ServiceStatus::Zapret { strategy } => Some(strategy),
        ServiceStatus::Connected { .. } => {
            let choice = state.choice.lock().ok()?.clone();
            (choice.mode.as_deref() == Some("hybrid"))
                .then(|| choice.zapret.strategy_for(network_key(state).as_deref()))
        }
        _ => None,
    }
}

async fn check_now(app: &AppHandle) -> CheckRecord {
    let state = app.state::<AppState>();
    let strategy = running_strategy(&state).await;
    let record = CheckRecord {
        at: now_unix(),
        strategy,
        check: measure().await,
    };
    if let Ok(mut last) = state.zapret_last.lock() {
        *last = Some(record.clone());
    }
    let _ = app.emit(CHECK_EVENT, &record);
    record
}

/// «Проверить сейчас»: открываются ли Discord и YouTube с текущими настройками.
#[tauri::command]
pub async fn zapret_check(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CheckRecord, String> {
    if state.zapret_picking.load(Ordering::SeqCst) {
        return Err("Идёт подбор стратегии".into());
    }
    Ok(check_now(&app).await)
}

#[tauri::command]
pub fn zapret_last(state: State<'_, AppState>) -> Option<CheckRecord> {
    state.zapret_last.lock().ok().and_then(|l| l.clone())
}

// ── Автоподбор ──

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    /// 0 — проверка без zapret, дальше — номер стратегии.
    index: usize,
    total: usize,
    title: String,
    score: Option<u32>,
    max: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tried {
    pub id: String,
    pub title: String,
    pub passed: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickResult {
    pub best: Option<String>,
    pub best_title: Option<String>,
    pub score: u32,
    pub max: u32,
    /// Сколько проверок проходит без zapret.
    pub baseline: u32,
    pub tested: usize,
    pub cancelled: bool,
    /// Все проверенные стратегии с результатом — для таблицы во вкладке Zapret.
    pub tried: Vec<Tried>,
}

/// Подбирает стратегию: сначала проверка без zapret, потом стратегии по порядку
/// Flowseal до первой, прошедшей все проверки. Итог запоминается для текущей сети.
#[tauri::command]
pub async fn zapret_autoselect(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<PickResult, String> {
    autoselect(&app, &state).await
}

async fn autoselect(app: &AppHandle, state: &AppState) -> Result<PickResult, String> {
    let before = query_status().await?;
    if matches!(before, Some(ServiceStatus::Connected { .. })) {
        return Err("Отключите VPN: подбор проверяет сайты напрямую, через zapret.".into());
    }
    if before.is_none() {
        return Err("Служба KVT не запущена.".into());
    }
    if state.zapret_picking.swap(true, Ordering::SeqCst) {
        return Err("Подбор уже идёт".into());
    }
    state.zapret_cancel.store(false, Ordering::SeqCst);
    let result = pick(app, state, before).await;
    state.zapret_picking.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
pub fn zapret_autoselect_cancel(state: State<'_, AppState>) {
    state.zapret_cancel.store(true, Ordering::SeqCst);
}

async fn pick(
    app: &AppHandle,
    state: &AppState,
    before: Option<ServiceStatus>,
) -> Result<PickResult, String> {
    // Подбор идёт минутами и сам переключает службу. Если за это время пользователь
    // подключился, отключился или сменил режим, подбор не трогает его выбор.
    let epoch = state.epoch();
    let acted = || state.epoch() != epoch;
    let strategies = zapret_strategies().await?;
    if strategies.is_empty() {
        return Err("Нет стратегий zapret. Нажмите «Переустановить» во вкладке Zapret.".into());
    }
    let choice = state
        .choice
        .lock()
        .map_err(crate::errors::state)?
        .zapret
        .clone();
    let network = network_key(state);
    let total = strategies.len();
    let progress = |index: usize, title: String, score: Option<u32>| {
        let _ = app.emit(
            PROGRESS_EVENT,
            Progress {
                index,
                total,
                title,
                score,
                max: MAX_SCORE,
            },
        );
    };

    // Без zapret: если всё и так открывается, подбирать нечего.
    let _ = call(Request::Disconnect).await;
    progress(0, "Без zapret".into(), None);
    let baseline = measure().await;
    progress(0, "Без zapret".into(), Some(baseline.passed));

    let mut best: Option<(Strategy, Check)> = None;
    let mut tried = Vec::new();
    let mut cancelled = false;
    if baseline.passed < MAX_SCORE {
        for (i, strategy) in strategies.iter().enumerate() {
            if state.zapret_cancel.load(Ordering::SeqCst) || acted() {
                cancelled = true;
                break;
            }
            progress(i + 1, strategy.title.clone(), None);
            let mut plan = choice.plan(network.as_deref());
            plan.strategy = strategy.id.clone();
            if call(Request::StartZapret(Box::new(plan))).await.is_err() {
                progress(i + 1, strategy.title.clone(), Some(0));
                tried.push(Tried {
                    id: strategy.id.clone(),
                    title: strategy.title.clone(),
                    passed: 0,
                });
                continue;
            }
            let check = measure().await;
            progress(i + 1, strategy.title.clone(), Some(check.passed));
            tried.push(Tried {
                id: strategy.id.clone(),
                title: strategy.title.clone(),
                passed: check.passed,
            });
            let full = check.passed == MAX_SCORE;
            if best.as_ref().map_or(true, |(_, b)| check.better_than(b)) {
                best = Some((strategy.clone(), check));
            }
            if full {
                break;
            }
        }
    }
    // Стратегия, которая не лучше, чем без zapret, не нужна.
    let best = best.filter(|(_, c)| c.passed > baseline.passed);
    if acted() {
        // Служба уже работает так, как решил пользователь, — не останавливаем её.
        crate::tray::refresh(app).await;
        return Err("Подбор прерван: подключение изменили во время проверки.".into());
    }

    if let Some((strategy, _)) = &best {
        let saved = state.choice.lock().ok().map(|mut c| {
            if let Some(key) = &network {
                c.zapret.by_network.insert(key.clone(), strategy.id.clone());
            }
            c.zapret.strategy = Some(strategy.id.clone());
            c.clone()
        });
        if let Some(c) = saved {
            save_choice(app, &c)?;
            let _ = app.emit(watchdog::CHOICE_EVENT, ());
        }
    }

    // Возвращаем как было: zapret работал — запускаем его с новой стратегией.
    let restart = matches!(before, Some(ServiceStatus::Zapret { .. }));
    let _ = call(Request::Disconnect).await;
    if restart {
        let plan = state
            .choice
            .lock()
            .map_err(crate::errors::state)?
            .zapret
            .plan(network.as_deref());
        let _ = call(Request::StartZapret(Box::new(plan))).await;
    }
    crate::tray::refresh(app).await;
    if let Some((strategy, check)) = &best {
        let record = CheckRecord {
            at: now_unix(),
            strategy: restart.then(|| strategy.id.clone()),
            check: check.clone(),
        };
        if let Ok(mut last) = state.zapret_last.lock() {
            *last = Some(record.clone());
        }
        let _ = app.emit(CHECK_EVENT, &record);
    }

    Ok(PickResult {
        best_title: best.as_ref().map(|(s, _)| s.title.clone()),
        score: best.as_ref().map_or(baseline.passed, |(_, c)| c.passed),
        best: best.map(|(s, _)| s.id),
        max: MAX_SCORE,
        baseline: baseline.passed,
        tested: tried.len(),
        cancelled,
        tried,
    })
}

// ── Автопроверка ──

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AutoEvent {
    /// Стратегия перестала работать, и KVT подобрал новую.
    Picked {
        title: String,
        passed: u32,
        max: u32,
    },
    /// Перестала работать, а подобрать не вышло (или автоподбор выключен, или гибрид).
    Unhealthy { passed: u32, max: u32 },
}

/// Раз в полчаса и после смены сети: открываются ли Discord и YouTube.
/// В режиме «Zapret» при сбое — автоподбор, если он разрешён.
pub fn spawn_watch(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            let state = app.state::<AppState>();
            let choice = state.choice.lock().map(|c| c.clone()).ok();
            let enabled = choice.as_ref().is_some_and(|c| c.zapret.auto_check);
            if enabled && !state.zapret_picking.load(Ordering::SeqCst) {
                if let Some(strategy) = running_strategy(&state).await {
                    let record = check_now(&app).await;
                    let zapret_only =
                        choice.as_ref().and_then(|c| c.mode.as_deref()) == Some("zapret");
                    let auto_pick = choice.as_ref().is_some_and(|c| c.zapret.auto_pick);
                    if !record.check.healthy() {
                        let picked = if zapret_only && auto_pick {
                            autoselect(&app, &state)
                                .await
                                .ok()
                                .filter(|r| r.best.is_some())
                        } else {
                            None
                        };
                        let event = match picked {
                            Some(r) => AutoEvent::Picked {
                                title: r.best_title.unwrap_or(strategy),
                                passed: r.score,
                                max: r.max,
                            },
                            None => AutoEvent::Unhealthy {
                                passed: record.check.passed,
                                max: record.check.max,
                            },
                        };
                        let _ = app.emit(AUTO_EVENT, event);
                    }
                }
            }
            // Смена сети будит раньше: дадим ей устояться.
            tokio::select! {
                _ = tokio::time::sleep(WATCH_INTERVAL) => {}
                _ = state.zapret_wake.notified() => {
                    tokio::time::sleep(Duration::from_secs(20)).await;
                }
            }
        }
    });
}

// ── «Почему не работает?» для zapret ──

/// Программы, которые, по опыту Flowseal, мешают zapret.
fn interferers() -> Vec<String> {
    let run = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
            .unwrap_or_default()
    };
    let tasks = run("tasklist", &["/FO", "CSV", "/NH"]);
    let services = run("sc", &["query"]);
    let mut out = Vec::new();
    if tasks.contains("\"adguardsvc.exe\"") {
        out.push("AdGuard — мешает Discord; добавьте Discord в исключения AdGuard".to_owned());
    }
    if tasks.contains("\"avp.exe\"") {
        out.push(
            "Антивирус Касперского — может блокировать WinDivert; добавьте папку KVT в исключения"
                .to_owned(),
        );
    }
    if services.contains("killer") {
        out.push("Killer Network Service — конфликтует с zapret; отключите его".to_owned());
    }
    if services
        .lines()
        .any(|l| l.contains("intel") && l.contains("connectivity") && l.contains("network"))
    {
        out.push("Intel Connectivity Network Service — конфликтует с zapret".to_owned());
    }
    if services.contains("tracsrvwrapper") || services.contains("epwd") {
        out.push("Check Point — конфликтует с zapret; его придётся удалить".to_owned());
    }
    if services.contains("smartbyte") {
        out.push("SmartByte — конфликтует с zapret; отключите его в «Службах»".to_owned());
    }
    out
}

/// Системный прокси: браузер пойдёт через него, а не через zapret.
fn system_proxy() -> Option<String> {
    let out = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let value = |name: &str| {
        text.lines()
            .find(|l| l.split_whitespace().next() == Some(name))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
    };
    (value("ProxyEnable").as_deref() == Some("0x1"))
        .then(|| value("ProxyServer").unwrap_or_default())
}

/// Включены ли TCP timestamps (`Get-NetTCPSetting` не зависит от языка Windows).
fn tcp_timestamps_enabled() -> Option<bool> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetTCPSetting -SettingName Internet).Timestamps",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "Enabled" => Some(true),
        "Disabled" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretFix {
    /// Переустановить комплект и драйвер.
    Repair,
    StopConflicts,
    Autoselect,
    AllowTimestamps,
    /// Включить режим «Zapret».
    Enable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZapretDiagnosis {
    pub tone: Tone,
    pub title: String,
    pub detail: String,
    pub steps: Vec<Step>,
    pub fix: Option<ZapretFix>,
    pub check: Option<Check>,
}

#[derive(Debug, Clone, Default)]
pub struct ZapretFacts {
    /// `None` — служба не отвечает.
    pub service: Option<ServiceStatus>,
    pub info: Option<ZapretInfo>,
    pub conflicts: Vec<Conflict>,
    pub interferers: Vec<String>,
    pub proxy: Option<String>,
    /// Работающая стратегия; `None` — zapret выключен.
    pub running: Option<String>,
    pub needs_timestamps: bool,
    pub timestamps_allowed: bool,
    pub timestamps_enabled: Option<bool>,
    pub check: Option<Check>,
}

fn step(steps: &mut Vec<Step>, title: &'static str, state: StepState, detail: impl Into<String>) {
    steps.push(Step {
        title,
        state,
        detail: detail.into(),
    });
}

pub fn conclude(f: &ZapretFacts) -> ZapretDiagnosis {
    let mut steps = Vec::new();
    let done = |steps: Vec<Step>, tone, title: &str, detail: String, fix| ZapretDiagnosis {
        tone,
        title: title.to_owned(),
        detail,
        steps,
        fix,
        check: f.check.clone(),
    };

    let Some(service) = &f.service else {
        step(
            &mut steps,
            "Служба KVT",
            StepState::Fail,
            "Служба не отвечает",
        );
        return done(
            steps,
            Tone::Error,
            "Служба KVT не запущена",
            "zapret запускает служба KVT. Запустите её (для разработки — kvt-service --console от администратора).".into(),
            None,
        );
    };
    step(&mut steps, "Служба KVT", StepState::Ok, "Работает");

    match &f.info {
        Some(info) if !info.ok => {
            step(
                &mut steps,
                "Файлы zapret",
                StepState::Fail,
                info.problem.clone().unwrap_or_default(),
            );
            return done(
                steps,
                Tone::Error,
                "Файлы zapret повреждены",
                "Части комплекта нет или файлы изменены. Переустановка вернёт проверенные файлы и драйвер WinDivert.".into(),
                Some(ZapretFix::Repair),
            );
        }
        Some(info) => step(
            &mut steps,
            "Файлы zapret",
            StepState::Ok,
            format!("Flowseal {}, стратегий: {}", info.version, info.strategies),
        ),
        None => {}
    }

    if !f.conflicts.is_empty() {
        let names: Vec<&str> = f.conflicts.iter().map(|c| c.name.as_str()).collect();
        step(
            &mut steps,
            "Другие обходы",
            StepState::Fail,
            names.join(", "),
        );
        return done(
            steps,
            Tone::Error,
            "Работает другой обход блокировок",
            format!(
                "{} обрабатывает те же пакеты — вместе с zapret KVT ничего не открывается. KVT может их остановить, ничего не удаляя.",
                names.join(", ")
            ),
            Some(ZapretFix::StopConflicts),
        );
    }
    step(&mut steps, "Другие обходы", StepState::Ok, "Не найдены");

    if let ServiceStatus::Failed { reason, .. } = service {
        if reason.contains("zapret") {
            step(&mut steps, "winws", StepState::Fail, reason.clone());
            return done(
                steps,
                Tone::Error,
                "zapret остановился",
                "winws завершился сам — чаще всего мешает драйвер WinDivert или антивирус. Переустановка ставит драйвер заново.".into(),
                Some(ZapretFix::Repair),
            );
        }
    }

    let Some(strategy) = &f.running else {
        step(&mut steps, "zapret", StepState::Warning, "Выключен");
        return done(
            steps,
            Tone::Warning,
            "zapret выключен",
            "Включите режим «Zapret» (без VPN) или «Гибрид» (YouTube и Discord через zapret, остальное через VPN).".into(),
            Some(ZapretFix::Enable),
        );
    };
    let title = kvt_core::zapret::title(strategy);
    step(
        &mut steps,
        "zapret",
        StepState::Ok,
        format!("Работает, стратегия «{title}»"),
    );

    for name in &f.interferers {
        step(
            &mut steps,
            "Мешающая программа",
            StepState::Warning,
            name.clone(),
        );
    }
    if let Some(proxy) = &f.proxy {
        step(
            &mut steps,
            "Системный прокси",
            StepState::Warning,
            format!("Включён ({proxy}) — браузер пойдёт через него, а не через zapret"),
        );
    }

    let Some(check) = &f.check else {
        return done(steps, Tone::Ok, "zapret работает", String::new(), None);
    };
    let state = if check.healthy() {
        StepState::Ok
    } else {
        StepState::Fail
    };
    step(
        &mut steps,
        "Discord и YouTube",
        state,
        format!("Открывается {} из {} проверок", check.passed, check.max),
    );
    if check.healthy() {
        let hint = if f.interferers.is_empty() && f.proxy.is_none() {
            String::new()
        } else {
            " Если что-то всё же не открывается в браузере — посмотрите предупреждения ниже.".into()
        };
        return done(
            steps,
            Tone::Ok,
            "zapret работает",
            format!(
                "Discord и YouTube открываются ({} из {}).{hint}",
                check.passed, check.max
            ),
            None,
        );
    }

    if f.needs_timestamps && (!f.timestamps_allowed || f.timestamps_enabled == Some(false)) {
        step(
            &mut steps,
            "TCP timestamps",
            StepState::Fail,
            "Выключены, а стратегия их требует",
        );
        return done(
            steps,
            Tone::Error,
            "Стратегии не хватает TCP timestamps",
            format!("Стратегия «{title}» работает только с TCP timestamps. Разрешите KVT включать их — так делает и Flowseal."),
            Some(ZapretFix::AllowTimestamps),
        );
    }
    if let Some(name) = f.interferers.first() {
        return done(
            steps,
            Tone::Error,
            "zapret мешает другая программа",
            format!("{name}. Если после этого не заработает — подберите стратегию."),
            Some(ZapretFix::Autoselect),
        );
    }
    done(
        steps,
        Tone::Error,
        "Стратегия не помогает в этой сети",
        format!(
            "С «{title}» открывается {} из {} проверок. Провайдеры блокируют по-разному — подберите стратегию. Если не поможет ни одна, переустановите zapret.",
            check.passed, check.max
        ),
        Some(ZapretFix::Autoselect),
    )
}

#[tauri::command]
pub async fn zapret_diagnose(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ZapretDiagnosis, String> {
    let service = query_status().await.ok().flatten();
    let mut facts = ZapretFacts {
        service: service.clone(),
        ..Default::default()
    };
    if service.is_some() {
        facts.info = zapret_info().await.ok();
        facts.conflicts = zapret_conflicts().await.unwrap_or_default();
        facts.running = running_strategy(&state).await;
        let choice = state
            .choice
            .lock()
            .map_err(crate::errors::state)?
            .zapret
            .clone();
        facts.timestamps_allowed = choice.tcp_timestamps;
        if let Some(running) = &facts.running {
            facts.needs_timestamps = zapret_strategies()
                .await
                .unwrap_or_default()
                .iter()
                .any(|s| &s.id == running && s.needs_timestamps);
        }
        let (interferers, proxy, timestamps) = tokio::task::spawn_blocking(move || {
            (interferers(), system_proxy(), tcp_timestamps_enabled())
        })
        .await
        .map_err(|e| e.to_string())?;
        facts.interferers = interferers;
        facts.proxy = proxy;
        facts.timestamps_enabled = timestamps;
        if facts.running.is_some() && facts.conflicts.is_empty() {
            facts.check = Some(check_now(&app).await.check);
        }
    }
    Ok(conclude(&facts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::ipc::DriverState;

    #[test]
    fn strategy_for_network_wins() {
        let mut c = ZapretChoice::default();
        assert_eq!(c.strategy_for(None), "general");
        c.strategy = Some("general (ALT4)".into());
        assert_eq!(c.strategy_for(Some("home")), "general (ALT4)");
        c.by_network
            .insert("home".into(), "general (FAKE TLS AUTO)".into());
        assert_eq!(c.strategy_for(Some("home")), "general (FAKE TLS AUTO)");
        assert_eq!(c.strategy_for(Some("cafe")), "general (ALT4)");
        assert!(c.tcp_timestamps && c.auto_check && c.auto_pick);
    }

    /// Свои домены из прежних версий в settings.json не ломают выбор и в zapret
    /// не попадают: остаются только списки Flowseal.
    #[test]
    fn old_user_domains_are_ignored() {
        let c: ZapretChoice = serde_json::from_str(
            r#"{"strategy":"general (ALT4)","userDomains":["twitch.tv"],"excludeDomains":["bank.ru"],"telegram":false}"#,
        )
        .unwrap();
        assert_eq!(c.strategy.as_deref(), Some("general (ALT4)"));
        let p = c.plan(None);
        assert!(p.domains.is_empty());
        assert!(p.exclude_domains.is_empty());
    }

    /// С прокси Telegram winws не трогает его соединения.
    #[test]
    fn telegram_proxy_is_excluded_from_zapret() {
        let c = ZapretChoice::default();
        assert!(c.telegram);
        let p = c.plan(None);
        assert!(p.exclude_domains.contains(&"web.telegram.org".to_owned()));
        assert!(p.exclude_domains.iter().any(|d| d.ends_with(".co.uk")));
        assert!(p
            .exclude_domains
            .iter()
            .all(|d| kvt_core::zapret::valid_domain(d)));
    }

    fn check(passed: u32) -> Check {
        Check {
            targets: Vec::new(),
            download: true,
            passed,
            max: MAX_SCORE,
            latency_ms: 100,
        }
    }

    #[test]
    fn health_threshold() {
        assert!(check(MAX_SCORE).healthy());
        assert!(check(MAX_SCORE - 2).healthy());
        assert!(!check(MAX_SCORE - 3).healthy());
        let mut slow = check(10);
        slow.latency_ms = 900;
        assert!(check(10).better_than(&slow));
        assert!(check(11).better_than(&check(10)));
    }

    fn info(ok: bool) -> ZapretInfo {
        ZapretInfo {
            version: "1.10.4".into(),
            bundled_version: "1.10.4".into(),
            updated: false,
            ok,
            problem: (!ok).then(|| "файл winws.exe изменён".into()),
            strategies: if ok { 22 } else { 0 },
            rejected: vec![],
            driver: DriverState::Running,
        }
    }

    fn healthy_facts() -> ZapretFacts {
        ZapretFacts {
            service: Some(ServiceStatus::Zapret {
                strategy: "general (ALT4)".into(),
            }),
            info: Some(info(true)),
            running: Some("general (ALT4)".into()),
            timestamps_allowed: true,
            timestamps_enabled: Some(true),
            check: Some(check(MAX_SCORE)),
            ..Default::default()
        }
    }

    #[test]
    fn healthy_zapret() {
        let d = conclude(&healthy_facts());
        assert_eq!(d.tone, Tone::Ok);
        assert_eq!(d.fix, None);
        assert!(d.steps.iter().all(|s| s.state == StepState::Ok));
    }

    #[test]
    fn broken_files_suggest_repair() {
        let mut f = healthy_facts();
        f.info = Some(info(false));
        let d = conclude(&f);
        assert_eq!(d.fix, Some(ZapretFix::Repair));
        assert_eq!(d.title, "Файлы zapret повреждены");
    }

    #[test]
    fn crashed_winws_suggests_repair() {
        let mut f = healthy_facts();
        f.service = Some(ServiceStatus::Failed {
            reason: "zapret остановился (exit code: 1)".into(),
            blocked: false,
        });
        f.running = None;
        assert_eq!(conclude(&f).fix, Some(ZapretFix::Repair));
    }

    #[test]
    fn conflicts_come_first() {
        let mut f = healthy_facts();
        f.conflicts = vec![Conflict {
            service: true,
            name: "GoodbyeDPI".into(),
        }];
        f.check = Some(check(0));
        assert_eq!(conclude(&f).fix, Some(ZapretFix::StopConflicts));
    }

    #[test]
    fn disabled_zapret_offers_enable() {
        let mut f = healthy_facts();
        f.service = Some(ServiceStatus::Disconnected);
        f.running = None;
        assert_eq!(conclude(&f).fix, Some(ZapretFix::Enable));
    }

    #[test]
    fn failing_strategy_with_timestamps_off() {
        let mut f = healthy_facts();
        f.check = Some(check(3));
        f.needs_timestamps = true;
        f.timestamps_enabled = Some(false);
        assert_eq!(conclude(&f).fix, Some(ZapretFix::AllowTimestamps));
        f.needs_timestamps = false;
        let d = conclude(&f);
        assert_eq!(d.fix, Some(ZapretFix::Autoselect));
        assert!(d.detail.contains("ALT4"));
    }

    #[test]
    fn interferer_is_named() {
        let mut f = healthy_facts();
        f.check = Some(check(2));
        f.interferers = vec!["Killer Network Service — конфликтует с zapret".into()];
        let d = conclude(&f);
        assert!(d.detail.contains("Killer"));
        assert_eq!(d.fix, Some(ZapretFix::Autoselect));
    }

    /// Цели из этой сети: `cargo test -p kvt-app real_zapret_targets -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "ходит на Discord и YouTube"]
    async fn real_zapret_targets() {
        let c = measure().await;
        println!("{} из {MAX_SCORE}, {} мс", c.passed, c.latency_ms);
        for t in &c.targets {
            println!("{:24} TLS1.3 {:?} TLS1.2 {:?}", t.name, t.tls13, t.tls12);
        }
        println!("загрузка: {}", c.download);
    }

    /// Последний релиз Flowseal: `cargo test -p kvt-app real_flowseal_release -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "ходит в API GitHub"]
    async fn real_flowseal_release() {
        let body = reqwest::Client::builder()
            .user_agent("KVT-test")
            .build()
            .unwrap()
            .get(kvt_core::zapret::RELEASES_API)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let r = kvt_core::zapret::parse_release(&body).unwrap();
        println!("{r:?}");
        assert!(kvt_core::zapret::valid_version(&r.version));
    }
}
