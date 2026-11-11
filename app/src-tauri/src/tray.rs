//! Трей — пульт KVT: всё, что меняют каждый день, — без окна. Левый клик
//! открывает окно, правый — меню: статус и сеанс, подключение, сервер, режим,
//! маршрутизация, стратегия zapret, kill switch, автопереключение, инструменты.
//!
//! Значок рисует `icon.rs`: цвет плитки — что работает, метка — что требует
//! внимания. Первая строка меню — тот же значок и статус, по клику открывает окно.
//!
//! Пункты меняют выбор тем же путём, что окно и автопереключение: `Choice` →
//! settings.json → событие `choice-changed` (окно перечитывает выбор) → при
//! работающем подключении — переподключение. Меню перестраивается по событиям
//! (`invalidate`), а раз в 5 с обновляются только статус, значок и подсказка.
//!
//! Закрытое окно уничтожается вместе с WebView, поэтому в фоне KVT почти не
//! занимает память.

use crate::{
    connect_current, disconnect_service, display_name, query_status, save_choice, watchdog,
    AppState,
};
use kvt_core::ipc::{Request, Response, ServiceStatus, Session};
use kvt_core::routing::Action;
use kvt_core::tester::Outcome;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::menu::{
    CheckMenuItem, IconMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu,
};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Listener, Manager, WebviewWindowBuilder, Wry};

const TRAY_ID: &str = "kvt";
/// Окно открывает страницу по имени (`Page` в NavRail.svelte).
pub const NAVIGATE_EVENT: &str = "navigate";
/// Серверов подписки в меню; остальные — в окне («Все серверы…»).
const SERVERS_IN_MENU: usize = 30;
/// Длина названия в пункте меню.
const NAME_LEN: usize = 40;
const REBUILD_DELAY: Duration = Duration::from_millis(500);

mod icon;

use icon::Tone;

/// Сторона значка трея и меню в пикселях: 16 при 100 % масштаба экрана.
fn icon_size(app: &AppHandle) -> u32 {
    let scale = app
        .primary_monitor()
        .ok()
        .flatten()
        .map_or(1.0, |m| m.scale_factor());
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let size = (16.0 * scale).round().clamp(16.0, 64.0) as u32;
    size
}

/// Период пульса значка при подключении.
const PULSE: Duration = Duration::from_millis(600);

/// Что видно в трее сейчас.
#[derive(Clone, PartialEq, Eq, Default)]
struct View {
    /// Вид статуса без подробностей: смена — повод перестроить меню.
    kind: &'static str,
    title: String,
    detail: String,
    tooltip: String,
}

struct Tray {
    /// Меню нужно перестроить (выбор, подписки, итоги проверок, статус).
    dirty: AtomicBool,
    /// Перестройка уже запланирована: события идут пачками (итоги проверки — сотнями).
    scheduled: AtomicBool,
    /// Заголовок меню (статус со значком и строка подробностей) — меняется без перестройки.
    header: Mutex<Option<(IconMenuItem<Wry>, MenuItem<Wry>)>>,
    shown: Mutex<(View, Option<Tone>)>,
    /// Пульс значка уже идёт.
    pulsing: AtomicBool,
    /// Стратегии из комплекта zapret: (id, название), только рекомендованные.
    strategies: Mutex<Vec<(String, String)>>,
    /// Последний статус: от него зависят «Подключить»/«Отключить».
    status: Mutex<Option<ServiceStatus>>,
    /// Перестройки идут по одной.
    building: Mutex<()>,
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon::render(Tone::Off, 0, icon_size(app)))
        .tooltip("KVT")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(Tray {
        dirty: AtomicBool::new(true),
        scheduled: AtomicBool::new(false),
        header: Mutex::default(),
        shown: Mutex::default(),
        pulsing: AtomicBool::new(false),
        strategies: Mutex::default(),
        status: Mutex::default(),
        building: Mutex::default(),
    });

    // Что меняется не из трея: окно, автопереключение, профили сетей, подписки, проверки.
    for event in [
        watchdog::CHOICE_EVENT,
        crate::subs::CHANGED_EVENT,
        crate::prober::RESULT_EVENT,
        crate::tunnel::EVENT,
    ] {
        let handle = app.clone();
        app.listen_any(event, move |_| invalidate(&handle));
    }

    // Локальный pipe — дешёвый запрос; так трей видит и подключения из окна,
    // и падение ядра.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            refresh(&handle).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    Ok(())
}

/// Меню устарело — перестроить через полсекунды: пачка событий даёт одну перестройку.
pub fn invalidate(app: &AppHandle) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    tray.dirty.store(true, Ordering::SeqCst);
    if tray.scheduled.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(REBUILD_DELAY).await;
        if let Some(tray) = app.try_state::<Tray>() {
            tray.scheduled.store(false, Ordering::SeqCst);
        }
        refresh(&app).await;
    });
}

/// Показывает окно; если оно было закрыто — создаёт заново из конфигурации.
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    if let Some(config) = app.config().app.windows.first() {
        match WebviewWindowBuilder::from_config(app, config).and_then(|b| b.build()) {
            #[cfg(debug_assertions)]
            Ok(window) => dev_dock_right(&window),
            #[cfg(not(debug_assertions))]
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "не удалось открыть окно KVT"),
        }
    }
}

/// Разработка: с `KVT_DEV_DOCK=right` (scripts/dev.ps1) окно встаёт к правому краю
/// экрана на всю высоту — рядом с редактором, и так после каждой пересборки.
#[cfg(debug_assertions)]
fn dev_dock_right(window: &tauri::WebviewWindow) {
    if std::env::var("KVT_DEV_DOCK").as_deref() != Ok("right") {
        return;
    }
    let Ok(Some(monitor)) = window.primary_monitor() else {
        return;
    };
    let area = monitor.work_area();
    // Не уже minWidth окна (720 логических пикселей), иначе оно вылезет за край.
    let min = (720.0 * monitor.scale_factor()).ceil() as u32;
    let width = (area.size.width * 2 / 5).max(min).min(area.size.width);
    // set_size задаёт область содержимого: рамку и заголовок вычитаем, чтобы окно
    // целиком влезло в рабочую область над панелью задач.
    let (frame_w, frame_h) = match (window.outer_size(), window.inner_size()) {
        (Ok(o), Ok(i)) => (
            o.width.saturating_sub(i.width),
            o.height.saturating_sub(i.height),
        ),
        _ => (0, 0),
    };
    let x = area.position.x + i32::try_from(area.size.width - width).unwrap_or(0);
    let _ = window.set_size(tauri::PhysicalSize::new(
        width.saturating_sub(frame_w),
        area.size.height.saturating_sub(frame_h),
    ));
    let _ = window.set_position(tauri::PhysicalPosition::new(x, area.position.y));
}

/// Открывает окно на странице `page` («why» — «Почему не работает?» с запуском).
/// Новое окно забирает страницу командой `take_page`, открытое — получает событие.
pub fn open_page(app: &AppHandle, page: &str) {
    if let Ok(mut p) = app.state::<AppState>().pending_page.lock() {
        *p = Some(page.to_owned());
    }
    let _ = app.emit(NAVIGATE_EVENT, page);
    show_main_window(app);
}

/// Страница, которую попросили открыть до появления окна.
#[tauri::command]
pub fn take_page(state: tauri::State<'_, AppState>) -> Option<String> {
    state.pending_page.lock().ok().and_then(|mut p| p.take())
}

/// Обновляет статус, значок и подсказку; перестраивает меню, если оно устарело.
pub async fn refresh(app: &AppHandle) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    let status = query_status().await.ok().flatten();
    // Прокси Telegram следует за режимом: zapret работает — работает и он.
    {
        let app = app.clone();
        let status = status.clone();
        tauri::async_runtime::spawn(async move {
            crate::tgproxy::sync(&app, status.as_ref()).await;
        });
    }
    if status.is_some()
        && tray
            .strategies
            .lock()
            .map(|s| s.is_empty())
            .unwrap_or(false)
    {
        load_strategies(app).await;
    }
    let state = app.state::<AppState>();
    let session = state.session.lock().ok().and_then(|s| *s);
    let tunnel = state.tunnel.lock().ok().and_then(|t| *t);
    let (view, tone) = describe(&state, status.as_ref(), session, tunnel);
    if let Ok(mut s) = tray.status.lock() {
        *s = status;
    }

    let _guard = tray.building.lock();
    let (before, tone_changed) = match tray.shown.lock() {
        Ok(shown) => (shown.0.kind, shown.1 != Some(tone)),
        Err(_) => ("", true),
    };
    let kind_changed = before != view.kind;
    if kind_changed {
        let reason = match tray.status.lock().ok().and_then(|s| s.clone()) {
            Some(ServiceStatus::Failed { reason, .. }) => Some(reason),
            _ => None,
        };
        crate::notify::status_changed(app, before, reason.as_deref());
    }
    if let Some(icon) = app.tray_by_id(TRAY_ID) {
        if tone_changed {
            let _ = icon.set_icon(Some(icon::render(tone, 0, icon_size(app))));
        }
        let _ = icon.set_tooltip(Some(&view.tooltip));
        if tray.dirty.swap(false, Ordering::SeqCst) || kind_changed {
            match build_menu(app, &tray, &view, tone) {
                Ok(menu) => {
                    let _ = icon.set_menu(Some(menu));
                }
                Err(e) => tracing::warn!(error = %e, "меню трея не построилось"),
            }
        } else if let Ok(header) = tray.header.lock() {
            if let Some((title, detail)) = header.as_ref() {
                let _ = title.set_text(&view.title);
                let _ = detail.set_text(&view.detail);
                if tone_changed {
                    let _ = title.set_icon(Some(icon::render(tone, 0, icon_size(app))));
                }
            }
        }
    }
    if let Ok(mut shown) = tray.shown.lock() {
        *shown = (view, Some(tone));
    };
    if tone.animated() && !tray.pulsing.swap(true, Ordering::SeqCst) {
        spawn_pulse(app.clone(), tone);
    }
}

/// Пульсирует значком, пока состояние не сменится; кадр 0 ставит `refresh`.
fn spawn_pulse(app: AppHandle, tone: Tone) {
    tauri::async_runtime::spawn(async move {
        let size = icon_size(&app);
        let mut frame = 0_u32;
        loop {
            tokio::time::sleep(PULSE).await;
            let Some(tray) = app.try_state::<Tray>() else {
                return;
            };
            // Под тем же замком, что и `refresh`: кадр не перезапишет новый значок.
            let _guard = tray.building.lock();
            let current = tray.shown.lock().ok().and_then(|s| s.1);
            if current != Some(tone) {
                tray.pulsing.store(false, Ordering::SeqCst);
                return;
            }
            frame = frame.wrapping_add(1);
            if let Some(icon) = app.tray_by_id(TRAY_ID) {
                let _ = icon.set_icon(Some(icon::render(tone, frame, size)));
            }
        }
    });
}

async fn load_strategies(app: &AppHandle) {
    if let Ok(Response::Strategies { strategies }) =
        crate::service_client::call(Request::ZapretStrategies).await
    {
        let list: Vec<(String, String)> = strategies
            .into_iter()
            .filter(|s| s.recommended)
            .map(|s| (s.id.clone(), strategy_title(&s.id)))
            .collect();
        if let Some(tray) = app.try_state::<Tray>() {
            if let Ok(mut s) = tray.strategies.lock() {
                *s = list;
            }
            tray.dirty.store(true, Ordering::SeqCst);
        }
    }
}

/// `general` → «Основная», `general (ALT4)` → «ALT4» (как `strategyTitle` в окне).
fn strategy_title(id: &str) -> String {
    match id
        .strip_prefix("general (")
        .and_then(|s| s.strip_suffix(')'))
    {
        Some(inner) => inner.to_owned(),
        None if id == "general" => "Основная".into(),
        None => id.to_owned(),
    }
}

fn mode_title(mode: &str) -> &'static str {
    match mode {
        "hybrid" => "Гибрид",
        "zapret" => "Zapret",
        _ => "VPN",
    }
}

/// 42 с → «меньше минуты», 4320 с → «1 ч 12 мин».
pub(crate) fn elapsed_text(secs: u64) -> String {
    let (h, m) = (secs / 3600, secs % 3600 / 60);
    match (h, m) {
        (0, 0) => "меньше минуты".into(),
        (0, m) => format!("{m} мин"),
        (h, 0) => format!("{h} ч"),
        (h, m) => format!("{h} ч {m} мин"),
    }
}

/// 84 МБ, 1,2 ГБ — коротко, для меню и подсказки.
pub(crate) fn bytes_text(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let text = if unit == 0 || value >= 10.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}").replace('.', ",")
    };
    format!("{text} {}", UNITS[unit])
}

/// Укорачивает название и экранирует `&` (в меню Windows это мнемоника).
fn menu_text(text: &str) -> String {
    shorten(text, NAME_LEN)
}

/// Значение в названии подменю — короче пункта, чтобы меню не раздувалось вширь.
fn menu_text_short(text: &str) -> String {
    shorten(text, 24)
}

fn shorten(text: &str, len: usize) -> String {
    let short: String = if text.chars().count() > len {
        let mut s: String = text.chars().take(len - 1).collect();
        s.push('…');
        s
    } else {
        text.to_owned()
    };
    short.replace('&', "&&")
}

fn describe(
    state: &AppState,
    status: Option<&ServiceStatus>,
    session: Option<Session>,
    tunnel: Option<bool>,
) -> (View, Tone) {
    let (mode, ks) = state
        .choice
        .lock()
        .map(|c| {
            (
                c.mode.clone().unwrap_or_else(|| "vpn".into()),
                c.kill_switch,
            )
        })
        .unwrap_or_else(|_| ("vpn".into(), false));
    let server = state.selected().map(|e| display_name(&e.server));
    let server_text = server.unwrap_or_else(|| "сервер не выбран".into());
    // «VPN · 1 ч 12 мин · ↓ 84 МБ»: что работает и сколько.
    let with_session = |head: String| {
        let mut t = head;
        if let Some(s) = session {
            t.push_str(" · ");
            t.push_str(&elapsed_text(s.secs));
            if let Some(rx) = s.rx {
                t.push_str(&format!(" · ↓ {}", bytes_text(rx)));
            }
        }
        t
    };
    // Вид, заголовок, подробности, вторая строка подсказки, значок.
    let (kind, title, detail, hint, tone) = match status {
        Some(ServiceStatus::Connected { .. }) if tunnel == Some(false) => (
            "connected",
            "Сайты не открываются".to_owned(),
            format!("{server_text} не пропускает данные"),
            format!("{server_text} не пропускает данные"),
            Tone::Warn,
        ),
        Some(ServiceStatus::Connected { .. }) => (
            "connected",
            format!("Подключено — {server_text}"),
            with_session(mode_title(&mode).to_owned()),
            format!("{} · {server_text}", mode_title(&mode)),
            Tone::Vpn,
        ),
        Some(ServiceStatus::Zapret { strategy }) => {
            let strategy = format!("стратегия {}", strategy_title(strategy));
            (
                "zapret",
                "Zapret работает".to_owned(),
                with_session(format!("Без VPN · {strategy}")),
                format!("Без VPN · {strategy}"),
                Tone::Zapret,
            )
        }
        Some(ServiceStatus::Connecting) => {
            let detail = if mode == "zapret" {
                "Zapret · без VPN".to_owned()
            } else {
                format!("{} · {server_text}", mode_title(&mode))
            };
            (
                "connecting",
                "Подключение…".to_owned(),
                detail.clone(),
                detail,
                Tone::Connecting,
            )
        }
        Some(ServiceStatus::Failed { reason, blocked }) => {
            if *blocked || (ks && reason.contains("Kill switch")) {
                let detail = "VPN остановился, kill switch не выпускает трафик".to_owned();
                (
                    "failed",
                    "Интернет закрыт".to_owned(),
                    detail.clone(),
                    detail,
                    Tone::Error,
                )
            } else {
                let short: String = reason.chars().take(60).collect();
                let detail = if short.len() < reason.len() {
                    format!("{short}…")
                } else {
                    short
                };
                (
                    "failed",
                    "Ошибка подключения".to_owned(),
                    detail.clone(),
                    detail,
                    Tone::Error,
                )
            }
        }
        Some(ServiceStatus::Disconnected) => {
            let detail = if mode == "zapret" {
                "Zapret · без VPN".to_owned()
            } else {
                format!("{} · {server_text}", mode_title(&mode))
            };
            (
                "disconnected",
                "Отключено".to_owned(),
                detail.clone(),
                detail,
                Tone::Off,
            )
        }
        None if crate::service_client::version_mismatch() => (
            "mismatch",
            "Окно и служба KVT разных версий".to_owned(),
            "Установите KVT заново — настройки сохранятся".to_owned(),
            "Установите KVT заново".to_owned(),
            Tone::Error,
        ),
        None => (
            "no_service",
            "Служба KVT не запущена".to_owned(),
            "Откройте KVT, чтобы запустить её".to_owned(),
            "Откройте KVT, чтобы запустить её".to_owned(),
            Tone::Error,
        ),
    };
    // Подсказка Windows — до 127 символов: «KVT — статус» и подробность.
    let tooltip: String = format!(
        "KVT — {}
{hint}",
        tooltip_title(kind, tone, &title)
    )
    .chars()
    .take(127)
    .collect();
    let view = View {
        kind,
        title: menu_text_long(&title),
        detail: menu_text_long(&detail),
        tooltip,
    };
    (view, tone)
}

/// Статус для подсказки: без названия сервера, оно во второй строке.
fn tooltip_title(kind: &str, tone: Tone, title: &str) -> String {
    match kind {
        "connected" if tone == Tone::Vpn => "подключено".to_owned(),
        "no_service" => "служба не запущена".to_owned(),
        "mismatch" => "окно и служба разных версий".to_owned(),
        _ => {
            let mut chars = title.chars();
            chars
                .next()
                .map(|c| c.to_lowercase().chain(chars).collect())
                .unwrap_or_default()
        }
    }
}

/// Заголовок длиннее названия сервера, но тоже без `&`-мнемоник.
fn menu_text_long(text: &str) -> String {
    text.replace('&', "&&")
}

/// Порядок серверов подписки в меню: рабочие по задержке, затем не проверенные,
/// затем неработающие. Выбранный всегда попадает в меню.
fn menu_servers<'a>(
    servers: &'a [crate::ServerSummary],
    outcomes: &HashMap<String, Outcome>,
    selected: Option<&str>,
) -> Vec<(&'a crate::ServerSummary, Option<String>)> {
    use kvt_core::probe::Verdict;
    let mut ranked: Vec<(u8, u64, usize, Option<String>)> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| match outcomes.get(&s.key) {
            Some(Outcome::Checked {
                verdict: Verdict::Works | Verdict::Slow,
                latency_ms,
            }) => (
                0,
                latency_ms.unwrap_or(u64::MAX),
                i,
                latency_ms.map(|ms| format!("{ms} мс")),
            ),
            Some(Outcome::Checked { .. }) => (2, 0, i, Some("не работает".into())),
            _ => (1, 0, i, None),
        })
        .collect();
    ranked.sort_by_key(|&(class, latency, i, _)| (class, latency, i));
    let mut picked: Vec<(usize, Option<String>)> = ranked
        .iter()
        .take(SERVERS_IN_MENU)
        .map(|(_, _, i, note)| (*i, note.clone()))
        .collect();
    if let Some(sel) = selected {
        if let Some((_, _, i, note)) = ranked.iter().find(|(_, _, i, _)| servers[*i].key == sel) {
            if !picked.iter().any(|(p, _)| p == i) {
                picked.push((*i, note.clone()));
            }
        }
    }
    picked.into_iter().map(|(i, n)| (&servers[i], n)).collect()
}

fn server_label(name: &str, note: Option<&str>) -> String {
    match note {
        Some(n) => format!("{} · {n}", menu_text(name)),
        None => menu_text(name),
    }
}

fn build_menu(app: &AppHandle, tray: &Tray, view: &View, tone: Tone) -> tauri::Result<Menu<Wry>> {
    let state = app.state::<AppState>();
    let choice = state.choice.lock().map(|c| c.clone()).unwrap_or_default();
    let mode = choice.mode.clone().unwrap_or_else(|| "vpn".into());
    let selected = choice.server.clone();
    let status = tray.status.lock().ok().and_then(|s| s.clone());
    let active = matches!(
        status,
        Some(ServiceStatus::Connected { .. } | ServiceStatus::Zapret { .. })
    );
    let connecting = matches!(status, Some(ServiceStatus::Connecting));
    // Ядро остановилось, а kill switch держит интернет закрытым.
    let blocked = matches!(status, Some(ServiceStatus::Failed { blocked: true, .. }));
    let service = status.is_some();

    let menu = Menu::new(app)?;
    let sep = || PredefinedMenuItem::separator(app);

    // Заголовок: значок и статус (клик открывает окно), под ним — сеанс.
    let title = IconMenuItem::with_id(
        app,
        "status",
        &view.title,
        true,
        Some(icon::render(tone, 0, icon_size(app))),
        None::<&str>,
    )?;
    let detail = MenuItem::with_id(app, "detail", &view.detail, false, None::<&str>)?;
    menu.append(&title)?;
    menu.append(&detail)?;
    if let Ok(mut h) = tray.header.lock() {
        *h = Some((title, detail));
    }
    menu.append(&sep()?)?;

    // Подключение.
    let can_connect = service && (mode == "zapret" || state.selected().is_some());
    let zapret_only =
        matches!(status, Some(ServiceStatus::Zapret { .. })) || (!active && mode == "zapret");
    let toggle = if active {
        let label = if zapret_only {
            "Выключить zapret"
        } else {
            "Отключить"
        };
        MenuItem::with_id(app, "toggle", label, true, None::<&str>)?
    } else if blocked {
        MenuItem::with_id(
            app,
            "toggle",
            "Отключить и вернуть интернет",
            true,
            None::<&str>,
        )?
    } else if connecting {
        MenuItem::with_id(app, "toggle", "Подключение…", false, None::<&str>)?
    } else {
        let label = if zapret_only {
            "Включить zapret"
        } else if service && !can_connect {
            "Подключить — выберите сервер"
        } else {
            "Подключить"
        };
        MenuItem::with_id(app, "toggle", label, can_connect, None::<&str>)?
    };
    menu.append(&toggle)?;
    if active {
        menu.append(&MenuItem::with_id(
            app,
            "reconnect",
            "Переподключить",
            true,
            None::<&str>,
        )?)?;
    }
    menu.append(&sep()?)?;

    // Сервер.
    let groups = state.groups.lock().map(|g| g.clone()).unwrap_or_default();
    let outcomes = state.outcomes.lock().map(|o| o.clone()).unwrap_or_default();
    let server_title = match state.selected() {
        Some(e) => format!("Сервер: {}", menu_text_short(&display_name(&e.server))),
        None => "Сервер".to_owned(),
    };
    let servers_menu = Submenu::with_id(app, "servers", server_title, true)?;
    let names: HashMap<&str, &crate::ServerSummary> = groups
        .iter()
        .flat_map(|g| g.servers.iter().map(|s| (s.key.as_str(), s)))
        .collect();
    let recent: Vec<&crate::ServerSummary> = choice
        .recent
        .iter()
        .filter_map(|k| names.get(k.as_str()).copied())
        .collect();
    if !recent.is_empty() {
        servers_menu.append(&MenuItem::with_id(
            app,
            "recent-title",
            "Недавние",
            false,
            None::<&str>,
        )?)?;
        for s in recent {
            servers_menu.append(&CheckMenuItem::with_id(
                app,
                format!("rsrv:{}", s.key),
                menu_text(&s.name),
                true,
                selected.as_deref() == Some(s.key.as_str()),
                None::<&str>,
            )?)?;
        }
        servers_menu.append(&sep()?)?;
    }
    let non_empty: Vec<&crate::catalog::Group> =
        groups.iter().filter(|g| !g.servers.is_empty()).collect();
    let add_servers = |target: &Submenu<Wry>, group: &crate::catalog::Group| -> tauri::Result<()> {
        for (s, note) in menu_servers(&group.servers, &outcomes, selected.as_deref()) {
            target.append(&CheckMenuItem::with_id(
                app,
                format!("srv:{}", s.key),
                server_label(&s.name, note.as_deref()),
                true,
                selected.as_deref() == Some(s.key.as_str()),
                None::<&str>,
            )?)?;
        }
        if group.servers.len() > SERVERS_IN_MENU {
            target.append(&MenuItem::with_id(
                app,
                format!("all:{}", group.id),
                format!("Все серверы ({})…", group.servers.len()),
                true,
                None::<&str>,
            )?)?;
        }
        Ok(())
    };
    match non_empty.as_slice() {
        [] => servers_menu.append(&MenuItem::with_id(
            app,
            "add",
            "Добавить подписку…",
            true,
            None::<&str>,
        )?)?,
        [only] => add_servers(&servers_menu, only)?,
        many => {
            for group in many {
                let sub = Submenu::new(
                    app,
                    format!("{} ({})", menu_text(&group.title), group.servers.len()),
                    true,
                )?;
                add_servers(&sub, group)?;
                servers_menu.append(&sub)?;
            }
        }
    }
    menu.append(&servers_menu)?;

    // Режим.
    let modes = Submenu::with_id(app, "modes", format!("Режим: {}", mode_title(&mode)), true)?;
    for (id, label) in [
        ("vpn", "VPN"),
        ("hybrid", "Гибрид — YouTube и Discord через zapret"),
        ("zapret", "Zapret — без VPN"),
    ] {
        modes.append(&CheckMenuItem::with_id(
            app,
            format!("mode:{id}"),
            label,
            true,
            mode == id,
            None::<&str>,
        )?)?;
    }
    menu.append(&modes)?;

    // Что через VPN — в «Zapret» VPN нет, и пункт не нужен.
    if mode != "zapret" {
        let proxy_all = choice.routing.everything_else == Action::Proxy;
        let route = Submenu::with_id(
            app,
            "route",
            if proxy_all {
                "Через VPN: всё, кроме российского"
            } else {
                "Через VPN: только заблокированное"
            },
            true,
        )?;
        route.append(&CheckMenuItem::with_id(
            app,
            "route:proxy",
            "Всё, кроме российского",
            true,
            proxy_all,
            None::<&str>,
        )?)?;
        route.append(&CheckMenuItem::with_id(
            app,
            "route:direct",
            "Только заблокированное",
            true,
            !proxy_all,
            None::<&str>,
        )?)?;
        menu.append(&route)?;
    }

    // Стратегия zapret — только там, где zapret работает.
    if mode != "vpn" {
        let network = crate::zapret::network_key(&state);
        let current = choice.zapret.strategy_for(network.as_deref());
        let mut list = tray
            .strategies
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        if !list.iter().any(|(id, _)| *id == current) {
            list.insert(0, (current.clone(), strategy_title(&current)));
        }
        let strategies = Submenu::with_id(
            app,
            "strategies",
            format!(
                "Стратегия zapret: {}",
                menu_text_short(&strategy_title(&current))
            ),
            true,
        )?;
        for (id, title) in list {
            strategies.append(&CheckMenuItem::with_id(
                app,
                format!("strat:{id}"),
                menu_text(&title),
                true,
                id == current,
                None::<&str>,
            )?)?;
        }
        strategies.append(&sep()?)?;
        strategies.append(&MenuItem::with_id(
            app,
            "strat-pick",
            "Подобрать заново…",
            true,
            None::<&str>,
        )?)?;
        menu.append(&strategies)?;
    }
    menu.append(&sep()?)?;

    menu.append(&CheckMenuItem::with_id(
        app,
        "ks",
        "Kill switch",
        true,
        choice.kill_switch,
        None::<&str>,
    )?)?;
    menu.append(&CheckMenuItem::with_id(
        app,
        "auto",
        "Автопереключение сервера",
        true,
        choice.auto_switch,
        None::<&str>,
    )?)?;
    menu.append(&sep()?)?;

    let tools = Submenu::with_id(app, "tools", "Инструменты", true)?;
    let tool_items: [(&str, &str); 3] = [
        ("tool:refresh", "Обновить подписки"),
        ("tool:why", "Почему не работает?"),
        ("tool:journal", "Журнал запросов"),
    ];
    for (id, label) in tool_items {
        tools.append(&MenuItem::with_id(app, id, label, true, None::<&str>)?)?;
    }
    menu.append(&tools)?;
    menu.append(&sep()?)?;

    let items: [&dyn IsMenuItem<Wry>; 2] = [
        &MenuItem::with_id(app, "open", "Открыть KVT", true, None::<&str>)?,
        &MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?,
    ];
    for item in items {
        menu.append(item)?;
    }
    Ok(menu)
}

fn on_menu(app: &AppHandle, id: &str) {
    let app = app.clone();
    let id = id.to_owned();
    match id.as_str() {
        "open" | "status" => show_main_window(&app),
        "add" => open_page(&app, "add"),
        "strat-pick" => open_page(&app, "zapret"),
        "tool:why" => open_page(&app, "why"),
        "tool:journal" => open_page(&app, "journal"),
        _ if id.starts_with("all:") => open_page(&app, "home"),
        _ => {
            tauri::async_runtime::spawn(async move {
                if let Err(message) = act(&app, &id).await {
                    crate::notify::error(&app, &message);
                }
                invalidate(&app);
            });
        }
    }
}

/// Работает VPN, zapret, и держит ли kill switch интернет закрытым после сбоя
/// (по последнему статусу).
fn active(app: &AppHandle) -> (bool, bool, bool) {
    let status = app
        .try_state::<Tray>()
        .and_then(|t| t.status.lock().ok().and_then(|s| s.clone()));
    (
        matches!(status, Some(ServiceStatus::Connected { .. })),
        matches!(status, Some(ServiceStatus::Zapret { .. })),
        matches!(status, Some(ServiceStatus::Failed { blocked: true, .. })),
    )
}

/// Меняет выбор, сохраняет и сообщает окну. Возвращает новый выбор.
fn change(app: &AppHandle, f: impl FnOnce(&mut crate::Choice)) -> Result<crate::Choice, String> {
    let state = app.state::<AppState>();
    let choice = {
        let mut c = state.choice.lock().map_err(crate::errors::state)?;
        f(&mut c);
        c.clone()
    };
    save_choice(app, &choice)?;
    let _ = app.emit(watchdog::CHOICE_EVENT, ());
    Ok(choice)
}

async fn reconnect(app: &AppHandle) -> Result<(), String> {
    connect_current(app, true).await.map(|_| ())
}

async fn act(app: &AppHandle, id: &str) -> Result<(), String> {
    if id != "auto" && id != "tool:refresh" {
        app.state::<AppState>().user_acted();
    }
    let (vpn, zapret, blocked) = active(app);
    let running = vpn || zapret;
    if let Some(key) = id.strip_prefix("srv:").or_else(|| id.strip_prefix("rsrv:")) {
        let choice = change(app, |c| {
            c.server = Some(key.to_owned());
            c.remember(key);
        })?;
        if vpn && choice.mode.as_deref() != Some("zapret") {
            reconnect(app).await?;
        }
        return Ok(());
    }
    if let Some(mode) = id.strip_prefix("mode:") {
        let old = app
            .state::<AppState>()
            .choice
            .lock()
            .ok()
            .and_then(|c| c.mode.clone())
            .unwrap_or_else(|| "vpn".into());
        if old == mode {
            return Ok(());
        }
        change(app, |c| c.mode = Some(mode.to_owned()))?;
        if running {
            reconnect(app).await?;
        }
        return Ok(());
    }
    if let Some(route) = id.strip_prefix("route:") {
        let action = if route == "direct" {
            Action::Direct
        } else {
            Action::Proxy
        };
        change(app, |c| c.routing.everything_else = action)?;
        if vpn {
            reconnect(app).await?;
        }
        return Ok(());
    }
    if let Some(strategy) = id.strip_prefix("strat:") {
        let network = crate::zapret::network_key(&app.state::<AppState>());
        let choice = change(app, |c| {
            c.zapret.strategy = Some(strategy.to_owned());
            if let Some(n) = &network {
                c.zapret.by_network.remove(n);
            }
        })?;
        if running && choice.mode.as_deref() != Some("vpn") {
            reconnect(app).await?;
        }
        return Ok(());
    }
    match id {
        "toggle" => {
            if running || blocked {
                disconnect_service().await?;
                crate::tunnel::set(app, None);
            } else {
                reconnect(app).await?;
            }
        }
        "reconnect" => reconnect(app).await?,
        "ks" => {
            change(app, |c| c.kill_switch = !c.kill_switch)?;
            // Kill switch ставит служба при подключении — применяем сразу.
            if vpn {
                reconnect(app).await?;
            }
        }
        "auto" => {
            change(app, |c| c.auto_switch = !c.auto_switch)?;
        }
        "tool:refresh" => {
            let failed = crate::subs::refresh_all(app).await?;
            if failed > 0 {
                return Err(format!(
                    "Не обновилось подписок: {failed}. Откройте KVT — у подписки будет видна причина."
                ));
            }
        }
        "quit" => quit(app).await,
        _ => {}
    }
    Ok(())
}

/// Явный выход — отключаем VPN, чтобы ядро не осталось работать без интерфейса.
async fn quit(app: &AppHandle) {
    let ks = app
        .state::<AppState>()
        .choice
        .lock()
        .map(|c| c.kill_switch)
        .unwrap_or(false);
    let (vpn, _, blocked) = active(app);
    let _ = disconnect_service().await;
    if ks && (vpn || blocked) {
        crate::notify::show(
            app,
            crate::notify::Notice {
                title: "KVT закрыт".into(),
                body: "VPN и kill switch выключены: интернет идёт напрямую.".into(),
                page: None,
                force: true,
            },
        );
    }
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_and_bytes_read_naturally() {
        assert_eq!(elapsed_text(42), "меньше минуты");
        assert_eq!(elapsed_text(5 * 60), "5 мин");
        assert_eq!(elapsed_text(3600), "1 ч");
        assert_eq!(elapsed_text(4320), "1 ч 12 мин");
        assert_eq!(bytes_text(512), "512 Б");
        assert_eq!(bytes_text(84 * 1024 * 1024), "84 МБ");
        assert_eq!(bytes_text(1_331_000_000), "1,2 ГБ");
    }

    #[test]
    fn menu_text_escapes_mnemonics_and_shortens() {
        assert_eq!(menu_text("R&D"), "R&&D");
        let long = "x".repeat(60);
        assert_eq!(menu_text(&long).chars().count(), NAME_LEN);
    }

    #[test]
    fn strategy_titles_match_window() {
        assert_eq!(strategy_title("general"), "Основная");
        assert_eq!(strategy_title("general (ALT4)"), "ALT4");
        assert_eq!(strategy_title("discord"), "discord");
    }
}
