//! Трей — основной способ пользоваться KVT: левый клик открывает окно, в меню
//! «Подключить/Отключить» и «Выход». Закрытое окно уничтожается вместе с
//! WebView, поэтому в фоне KVT почти не занимает память.

use crate::{connect_current, disconnect_service, query_status};
use kvt_core::ipc::ServiceStatus;
use std::sync::Mutex;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewWindowBuilder, Wry};

const TRAY_ID: &str = "kvt";

struct TrayMenu {
    toggle: MenuItem<Wry>,
    connected: Mutex<bool>,
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Открыть KVT", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Подключить", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &toggle, &quit])?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("KVT — отключено")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "toggle" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { toggle_connection(&app).await });
            }
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    // Явный выход — отключаем VPN, чтобы ядро не осталось работать без интерфейса.
                    let _ = disconnect_service().await;
                    app.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    app.manage(TrayMenu {
        toggle,
        connected: Mutex::new(false),
    });

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

/// Показывает окно; если оно было закрыто — создаёт заново из конфигурации.
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    if let Some(config) = app.config().app.windows.first() {
        if let Err(e) = WebviewWindowBuilder::from_config(app, config).and_then(|b| b.build()) {
            tracing::error!(error = %e, "не удалось открыть окно KVT");
        }
    }
}

/// Обновляет текст пункта меню и подсказку трея по статусу службы.
pub async fn refresh(app: &AppHandle) {
    let status = query_status().await.ok().flatten();
    let connected = matches!(
        status,
        Some(ServiceStatus::Connected { .. } | ServiceStatus::Zapret { .. })
    );
    let tooltip = match &status {
        Some(ServiceStatus::Connected { .. }) => "KVT — подключено",
        Some(ServiceStatus::Zapret { .. }) => "KVT — работает zapret",
        Some(ServiceStatus::Connecting) => "KVT — подключение…",
        Some(ServiceStatus::Failed { .. }) => "KVT — ошибка подключения",
        Some(ServiceStatus::Disconnected) => "KVT — отключено",
        None => "KVT — служба не запущена",
    };
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(tooltip));
    }
    if let Some(menu) = app.try_state::<TrayMenu>() {
        let _ = menu.toggle.set_text(if connected {
            "Отключить"
        } else {
            "Подключить"
        });
        if let Ok(mut c) = menu.connected.lock() {
            *c = connected;
        }
    }
}

async fn toggle_connection(app: &AppHandle) {
    let connected = app
        .try_state::<TrayMenu>()
        .and_then(|m| m.connected.lock().ok().map(|c| *c))
        .unwrap_or(false);
    let result = if connected {
        disconnect_service().await.map(|_| ())
    } else {
        connect_current(app, true).await.map(|_| ())
    };
    refresh(app).await;
    // Ошибку (не выбран сервер, служба не запущена) видно только в окне.
    if result.is_err() {
        show_main_window(app);
    }
}
