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

use crate::{connect_current, disconnect_service, display_name, query_status, watchdog, AppState};
use kvt_core::i18n::tr;
use kvt_core::ipc::{Request, Response, ServiceStatus, Session};
use kvt_core::routing::Action;
use kvt_core::tester::Outcome;
use kvt_core::trf;
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

mod actions;
mod menu;
mod panel;
mod text;
mod window;

// Что зовут окно, служба уведомлений и main.rs — доступно как `tray::…`.
use actions::*;
use menu::*;
pub use panel::*;
pub(crate) use text::*;
pub use window::*;

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

pub(crate) struct Tray {
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
    /// Мини-панель у значка (`panel`).
    panel: panel::PanelState,
}

impl Tray {
    /// Язык сменился: статус и названия стратегий перечитать заново.
    pub(crate) fn forget_texts(&self) {
        if let Ok(mut shown) = self.shown.lock() {
            *shown = Default::default();
        }
        if let Ok(mut s) = self.strategies.lock() {
            s.clear();
        }
        self.dirty.store(true, Ordering::SeqCst);
    }
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon::render(Tone::Off, 0, icon_size(app)))
        .tooltip("KVT")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| match event {
            // Левый клик — мини-панель (или окно, если панель выключена), правый — меню.
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state,
                rect,
                position,
                ..
            } => panel::on_click(
                tray.app_handle(),
                matches!(button_state, MouseButtonState::Up),
                panel::icon_area(&rect, position),
            ),
            TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => panel::on_double_click(tray.app_handle()),
            _ => {}
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
        panel: panel::PanelState::default(),
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
    fn elapsed_and_bytes_in_english() {
        use kvt_core::i18n::{with, Lang};
        with(Lang::En, || {
            assert_eq!(elapsed_text(42), "under a minute");
            assert_eq!(elapsed_text(4320), "1 h 12 min");
            assert_eq!(bytes_text(1_331_000_000), "1.2 GB");
        });
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
