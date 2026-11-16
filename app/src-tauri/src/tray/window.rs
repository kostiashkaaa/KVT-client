//! Главное окно из трея: создать по требованию, показать страницу, у правого края
//! экрана при разработке.

use super::*;

/// Показывает окно; если оно было закрыто — создаёт заново из конфигурации.
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    if let Some(config) = app.config().app.windows.first() {
        match WebviewWindowBuilder::from_config(app, config)
            .and_then(|b| crate::mica::prepare(b).build())
        {
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
pub(super) fn dev_dock_right(window: &tauri::WebviewWindow) {
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
