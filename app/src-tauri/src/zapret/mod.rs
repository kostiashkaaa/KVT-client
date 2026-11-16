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
use crate::{connect_current, query_status, service_client, watchdog, AppState};
use kvt_core::i18n::tr;
use kvt_core::ipc::{
    Conflict, MaintenanceReport, Request, Response, ServiceStatus, ZapretInfo, ZapretPlan,
};
use kvt_core::trf;
use kvt_core::zapret::{GameFilter, Release, Strategy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::windows::process::CommandExt as _;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

mod autoselect;
mod check;
mod diagnose;
mod watch;

// Команды окна (`generate_handler!` в main.rs) и то, что зовут трей и профили сетей,
// доступны как `zapret::…`, как до разбиения на модули.
pub use autoselect::*;
pub use check::*;
pub use diagnose::*;
pub use watch::*;

/// Стратегия по умолчанию — основная у Flowseal.
pub const DEFAULT_STRATEGY: &str = "general";
pub const PROGRESS_EVENT: &str = "zapret-progress";
/// Итог проверки (ручной или автоматической).
pub const CHECK_EVENT: &str = "zapret-check";
/// Автопроверка что-то сделала сама или требует внимания.
pub const AUTO_EVENT: &str = "zapret-auto";

/// Название (по-русски и по-английски) и адрес.
const TARGETS: &[(&str, &str, &str)] = &[
    ("Discord", "Discord", "https://discord.com/"),
    (
        "Discord: подключение",
        "Discord: gateway",
        "https://gateway.discord.gg/",
    ),
    (
        "Discord: файлы",
        "Discord: files",
        "https://cdn.discordapp.com/",
    ),
    ("YouTube", "YouTube", "https://www.youtube.com/"),
    (
        "YouTube: картинки",
        "YouTube: images",
        "https://i.ytimg.com/",
    ),
    (
        "YouTube: видео",
        "YouTube: video",
        "https://redirector.googlevideo.com/",
    ),
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

#[tauri::command]
pub async fn zapret_strategies() -> Result<Vec<Strategy>, String> {
    match call(Request::ZapretStrategies).await? {
        Response::Strategies { strategies } => Ok(strategies),
        _ => Err(crate::errors::unexpected().into()),
    }
}

#[tauri::command]
pub async fn zapret_conflicts() -> Result<Vec<Conflict>, String> {
    match call(Request::ZapretConflicts).await? {
        Response::Conflicts { conflicts } => Ok(conflicts),
        _ => Err(crate::errors::unexpected().into()),
    }
}

/// Остановить чужие обходы — только по кнопке пользователя.
#[tauri::command]
pub async fn zapret_stop_conflicts() -> Result<Vec<Conflict>, String> {
    match call(Request::StopConflicts).await? {
        Response::Conflicts { conflicts } => Ok(conflicts),
        _ => Err(crate::errors::unexpected().into()),
    }
}

#[tauri::command]
pub async fn zapret_info() -> Result<ZapretInfo, String> {
    match call(Request::ZapretInfo).await? {
        Response::ZapretInfo(info) => Ok(*info),
        _ => Err(crate::errors::unexpected().into()),
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
                    .map_or(tr("версия Flowseal", "Flowseal version"), String::as_str),
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
        return Err(tr(
            "Идёт подбор стратегии — дождитесь его окончания",
            "A strategy is being picked — wait until it finishes",
        )
        .into());
    }
    let before = query_status().await?;
    let report = match call(request).await? {
        Response::Maintenance(report) => *report,
        _ => return Err(crate::errors::unexpected().into()),
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
