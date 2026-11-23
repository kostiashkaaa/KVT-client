//! Мини-панель у значка в трее: статус, подключение, режим, сервер, сервисы и быстрые
//! переключатели без главного окна. Дополнительная функция — выключается в «Настройках»
//! (`Choice.mini_panel`); выключена — клик по значку открывает окно, как раньше.
//!
//! Окно `mini` — отдельная страница `mini.html` (кода главного окна в ней нет, поэтому
//! старт быстрый, а память меньше). Оно создаётся скрытым по клику, показывается, когда
//! страница измерила содержимое и сообщила высоту (`panel_ready`; так нет белой
//! вспышки). После закрытия окно живёт ещё минуту: повторное открытие за это время
//! мгновенное — WebView уже создан; не открыли — уничтожается, и в фоне WebView
//! памяти не занимает.
//!
//! Высота зависит от состояния (плашка проблемы, список серверов, режим «Zapret» без
//! сервера), поэтому страница сообщает её при каждом изменении, а Rust заново ставит
//! панель у того же края: при панели задач снизу панель растёт вверх.
//!
//! Действия — те же, что в меню трея (`panel_act` → `actions::act`): выбор, сохранение,
//! `choice-changed` и переподключение там уже есть, своей логики у панели нет.

use super::*;
use place::{click_closes, fit_height, panel_position, Area};
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tauri::{PhysicalPosition, PhysicalSize, WebviewUrl, WebviewWindow, WindowEvent};

mod place;
mod view;

pub(crate) use view::PanelView;

const LABEL: &str = "mini";
/// Ширина панели, логические пиксели.
const WIDTH: f64 = 360.0;
/// Высота до первого замера страницы.
const FIRST_HEIGHT: f64 = 420.0;
/// Отступ от края рабочей области, логические пиксели.
const MARGIN: f64 = 12.0;
/// Страница не сообщила высоту за это время (не загрузилась) — окно закрывается.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Сколько пинг окна годится для показа в панели.
const PING_TTL: Duration = Duration::from_secs(60 * 60);
/// Сколько скрытое окно живёт после закрытия: повторное открытие за это время
/// мгновенное, WebView уже создан. Не открыли — уничтожаем.
const KEEP_ALIVE: Duration = Duration::from_secs(60);

/// Куда нажали и что с панелью сейчас. Лежит в `Tray`.
#[derive(Default)]
pub(super) struct PanelState {
    /// Значок, от которого панель встаёт; по нему же она переставляется при смене высоты.
    anchor: Mutex<Option<Area>>,
    /// Последняя высота страницы (логические пиксели) — для пересчёта при смене масштаба.
    height: Mutex<f64>,
    /// Когда панель скрылась из-за потери фокуса (клик мимо или по значку).
    blurred_at: Mutex<Option<Instant>>,
    /// Нажатие на значок закрывает панель: отпускание её заново не открывает.
    swallow_up: AtomicBool,
    /// Окно получило фокус хотя бы раз: потеря фокуса до этого — не клик мимо.
    focused: AtomicBool,
    /// Панель открыта: показывать окно можно только по этому знаку — страница живого
    /// окна меряет себя и после закрытия, и без знака панель выскочила бы сама.
    opened: AtomicBool,
    /// Страница ответила (`panel_ready`) в этом открытии: таймер «страница не
    /// ответила» касается только тех открытий, где ответа не было.
    ready: AtomicBool,
    /// Номер открытия: таймер «страница не ответила» и отложенное уничтожение
    /// относятся к своему открытию.
    generation: AtomicU64,
}

fn enabled(app: &AppHandle) -> bool {
    app.state::<AppState>()
        .choice
        .lock()
        .map_or(true, |c| c.mini_panel)
}

fn is_open(app: &AppHandle) -> bool {
    app.get_webview_window(LABEL)
        .is_some_and(|w| w.is_visible().unwrap_or(false))
}

/// Значок трея в физических пикселях экрана. Размер ноль (Windows не всегда его
/// сообщает) — место нажатия.
pub(super) fn icon_area(rect: &tauri::Rect, click: PhysicalPosition<f64>) -> Area {
    let position = rect.position.to_physical::<i32>(1.0);
    let size = rect.size.to_physical::<u32>(1.0);
    if size.width == 0 || size.height == 0 {
        return Area {
            x: px(click.x),
            y: px(click.y),
            w: 1,
            h: 1,
        };
    }
    Area {
        x: position.x,
        y: position.y,
        w: i32::try_from(size.width).unwrap_or(i32::MAX),
        h: i32::try_from(size.height).unwrap_or(i32::MAX),
    }
}

#[allow(clippy::cast_possible_truncation)]
fn px(v: f64) -> i32 {
    v.round() as i32
}

/// Левая кнопка на значке: `up` — отпускание. Нажатие только запоминает, закроет ли оно
/// панель (см. `click_closes`), действует отпускание.
pub(super) fn on_click(app: &AppHandle, up: bool, icon: Area) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    if !enabled(app) {
        if up {
            show_main_window(app);
        }
        return;
    }
    let panel = &tray.panel;
    if !up {
        let blurred = panel.blurred_at.lock().ok().and_then(|b| *b);
        let closes = click_closes(is_open(app), blurred, Instant::now());
        panel.swallow_up.store(closes, Ordering::SeqCst);
        return;
    }
    if panel.swallow_up.swap(false, Ordering::SeqCst) {
        close(app);
        return;
    }
    open(app, icon);
}

/// Двойной клик по значку — окно KVT; панель, открытую первым кликом, закрываем.
pub(super) fn on_double_click(app: &AppHandle) {
    if let Some(tray) = app.try_state::<Tray>() {
        // Отпускание после двойного клика — ещё один «клик».
        tray.panel.swallow_up.store(true, Ordering::SeqCst);
    }
    close(app);
    show_main_window(app);
}

fn open(app: &AppHandle, icon: Area) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    // Номер открытия: закрывает счёт отложенному уничтожению и относится к таймеру
    // «страница не ответила» этого открытия.
    let generation = tray.panel.generation.fetch_add(1, Ordering::SeqCst) + 1;

    // Окно живёт с прошлого открытия (скрытое, до `KEEP_ALIVE`): поставить заново у
    // значка и показать — WebView уже создан, открытие мгновенное.
    if let Some(window) = app.get_webview_window(LABEL) {
        if window.is_visible().unwrap_or(false) {
            return;
        }
        if let Ok(mut a) = tray.panel.anchor.lock() {
            *a = Some(icon);
        }
        tray.panel.opened.store(true, Ordering::SeqCst);
        tray.panel.focused.store(false, Ordering::SeqCst);
        // Страница живого окна уже измерила себя при прошлом открытии.
        tray.panel.ready.store(true, Ordering::SeqCst);
        let height = tray.panel.height.lock().map_or(FIRST_HEIGHT, |h| *h);
        place(app, &window, height);
        return;
    }

    if let Ok(mut a) = tray.panel.anchor.lock() {
        *a = Some(icon);
    }
    if let Ok(mut h) = tray.panel.height.lock() {
        *h = FIRST_HEIGHT;
    }
    tray.panel.opened.store(true, Ordering::SeqCst);
    tray.panel.focused.store(false, Ordering::SeqCst);
    tray.panel.ready.store(false, Ordering::SeqCst);

    let built = crate::mica::prepare_panel(WebviewWindowBuilder::new(
        app,
        LABEL,
        WebviewUrl::App("mini.html".into()),
    ))
    .title("KVT")
    .inner_size(WIDTH, FIRST_HEIGHT)
    .decorations(false)
    .shadow(true)
    .resizable(false)
    .maximizable(false)
    .minimizable(false)
    .skip_taskbar(true)
    .always_on_top(true)
    .visible(false)
    .focused(true)
    .build();
    match built {
        Ok(window) => {
            watch(app, &window);
            spawn_timeout(app.clone(), generation);
        }
        Err(e) => {
            tracing::error!(error = %e, "не удалось открыть мини-панель");
            show_main_window(app);
        }
    }
}

/// Потеря фокуса — клик мимо панели: скрываем. Смена масштаба (панель перенесли на
/// монитор с другим) — ставим заново.
fn watch(app: &AppHandle, window: &WebviewWindow) {
    let app = app.clone();
    let watched = window.clone();
    window.on_window_event(move |event| match event {
        WindowEvent::Focused(true) => {
            if let Some(tray) = app.try_state::<Tray>() {
                tray.panel.focused.store(true, Ordering::SeqCst);
            }
        }
        WindowEvent::Focused(false) => {
            let Some(tray) = app.try_state::<Tray>() else {
                return;
            };
            if !tray.panel.focused.load(Ordering::SeqCst) {
                return;
            }
            // Панель ещё не показана: при создании WebView на миг получает фокус и тут же
            // отдаёт его — окно скрыто, и это не «клик мимо». Закрывать нельзя.
            if !watched.is_visible().unwrap_or(false) {
                return;
            }
            if let Ok(mut b) = tray.panel.blurred_at.lock() {
                *b = Some(Instant::now());
            }
            close(&app);
        }
        WindowEvent::ScaleFactorChanged { .. } => {
            let Some(window) = app.get_webview_window(LABEL) else {
                return;
            };
            let height = app
                .try_state::<Tray>()
                .and_then(|t| t.panel.height.lock().ok().map(|h| *h))
                .unwrap_or(FIRST_HEIGHT);
            place(&app, &window, height);
        }
        _ => {}
    });
}

/// Страница не позвала `panel_ready` — закрыть окно, чтобы значок снова открывал
/// панель. Живое окно, которое просто закрыли до минуты, не трогает.
fn spawn_timeout(app: AppHandle, generation: u64) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(READY_TIMEOUT).await;
        let Some(tray) = app.try_state::<Tray>() else {
            return;
        };
        let current = tray.panel.generation.load(Ordering::SeqCst) == generation;
        let ready = tray.panel.ready.load(Ordering::SeqCst);
        let Some(window) = app.get_webview_window(LABEL) else {
            return;
        };
        if current && !ready && !window.is_visible().unwrap_or(false) {
            tracing::warn!("мини-панель не загрузилась за {READY_TIMEOUT:?}");
            let _ = window.destroy();
        }
    });
}

/// Скрывает панель сразу; окно живёт ещё `KEEP_ALIVE`, чтобы повторное открытие было
/// мгновенным. За минуту не открыли — уничтожается: в фоне WebView памяти не занимает.
pub(super) fn close(app: &AppHandle) {
    let Some(window) = app.get_webview_window(LABEL) else {
        return;
    };
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    tray.panel.opened.store(false, Ordering::SeqCst);
    let close_gen = tray.panel.generation.load(Ordering::SeqCst);
    let _ = window.hide();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(KEEP_ALIVE).await;
        let Some(tray) = app.try_state::<Tray>() else {
            return;
        };
        // Открыли заново — это открытие закроет окно своим порядком.
        if tray.panel.generation.load(Ordering::SeqCst) != close_gen {
            return;
        }
        if let Some(window) = app.get_webview_window(LABEL) {
            if window.is_visible().unwrap_or(true) {
                return;
            }
            let _ = window.destroy();
        }
    });
}

/// Ставит панель высотой `height` (логические пиксели) у значка и, если она ещё скрыта,
/// показывает.
fn place(app: &AppHandle, window: &WebviewWindow, height: f64) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    // Панель закрыта: страница живого окна меряет себя и после закрытия, но показывать
    // окно можно только по знаку пользователя — иначе панель выскочила бы сама.
    if !tray.panel.opened.load(Ordering::SeqCst) {
        return;
    }
    let Some(icon) = tray.panel.anchor.lock().ok().and_then(|a| *a) else {
        return;
    };
    let monitor = app
        .monitor_from_point(
            f64::from(icon.x + icon.w / 2),
            f64::from(icon.y + icon.h / 2),
        )
        .ok()
        .flatten()
        .or_else(|| app.primary_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return;
    };
    let wa = monitor.work_area();
    let work = Area {
        x: wa.position.x,
        y: wa.position.y,
        w: i32::try_from(wa.size.width).unwrap_or(i32::MAX),
        h: i32::try_from(wa.size.height).unwrap_or(i32::MAX),
    };
    let visible = window.is_visible().unwrap_or(false);
    if !visible {
        // Сначала на нужный монитор: масштаб окна и страницы станет его масштабом.
        let _ = window.set_position(PhysicalPosition::new(work.x, work.y));
    }
    let scale = window
        .scale_factor()
        .unwrap_or_else(|_| monitor.scale_factor());
    let margin = px(MARGIN * scale);
    let size = (
        px(WIDTH * scale),
        fit_height(px(height * scale), work, margin),
    );
    let (x, y) = panel_position(icon, work, size, margin);
    let _ = window.set_size(PhysicalSize::new(
        u32::try_from(size.0).unwrap_or(1),
        u32::try_from(size.1).unwrap_or(1),
    ));
    let _ = window.set_position(PhysicalPosition::new(x, y));
    if !visible {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Страница измерила содержимое: поставить панель и показать (при первом вызове).
#[tauri::command]
pub fn panel_ready(app: AppHandle, window: WebviewWindow, height: f64) {
    if window.label() != LABEL || !height.is_finite() || height < 1.0 {
        return;
    }
    if let Some(tray) = app.try_state::<Tray>() {
        if let Ok(mut h) = tray.panel.height.lock() {
            *h = height;
        }
        tray.panel.ready.store(true, Ordering::SeqCst);
    }
    place(&app, &window, height);
}

/// Esc на панели.
#[tauri::command]
pub fn panel_close(app: AppHandle, window: WebviewWindow) {
    if window.label() == LABEL {
        close(&app);
    }
}

/// «Открыть KVT», «Почему не работает?», «Настройки»: страница главного окна; без
/// страницы — окно как есть. Панель закрывается.
#[tauri::command]
pub fn panel_open(app: AppHandle, window: WebviewWindow, page: Option<String>) {
    if window.label() != LABEL {
        return;
    }
    close(&app);
    match page.as_deref() {
        None => show_main_window(&app),
        Some(p @ ("home" | "add" | "subscriptions" | "why" | "settings" | "zapret")) => {
            open_page(&app, p)
        }
        Some(_) => {}
    }
}

/// Действие панели — тот же пункт меню трея. Ждёт его конца, чтобы страница показывала
/// «Подключение…» и не гадала, когда читать статус. Ошибка — уведомлением, как в трее.
#[tauri::command]
pub async fn panel_act(app: AppHandle, window: WebviewWindow, id: String) {
    let known = matches!(id.as_str(), "toggle" | "ks" | "auto" | "tg")
        || id.starts_with("srv:")
        || id.starts_with("mode:");
    if window.label() == LABEL && known {
        run_action(&app, &id).await;
    }
}

/// Пинги окна не старше часа: условия сети меняются, а старая цифра выглядела бы как
/// сегодняшняя.
fn fresh_pings(state: &AppState) -> HashMap<String, kvt_core::tester::QuickResult> {
    let now = Instant::now();
    state.pings.lock().map_or_else(
        |_| HashMap::new(),
        |pings| {
            pings
                .iter()
                .filter(|(_, (_, at))| now.saturating_duration_since(*at) < PING_TTL)
                .map(|(key, (result, _))| (key.clone(), result.clone()))
                .collect()
        },
    )
}

/// Данные панели: выбор, серверы с пингом, подписка выбранного сервера.
/// `async` — не на главном потоке: панель спрашивает раз в 3 с, а сборка
/// клонирует и сортирует весь каталог.
#[tauri::command]
pub async fn panel_snapshot(
    window: WebviewWindow,
    state: tauri::State<'_, AppState>,
) -> Result<PanelView, String> {
    if window.label() != LABEL {
        return Err(String::new());
    }
    let choice = state.choice.lock().map_err(crate::errors::state)?.clone();
    let groups = state.groups.lock().map_err(crate::errors::state)?.clone();
    let outcomes = state.outcomes.lock().map_err(crate::errors::state)?.clone();
    let pings = fresh_pings(&state);
    let network = state.network.lock().map_err(crate::errors::state)?.clone();
    Ok(view::build(
        &choice,
        &groups,
        &outcomes,
        &pings,
        network.as_ref(),
    ))
}
