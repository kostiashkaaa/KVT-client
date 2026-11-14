//! Уведомления Windows, пока окно закрыто: сервер заменён, соединение прервано,
//! kill switch держит блокировку, zapret перестал справляться, ошибка действия из
//! трея. Без звука, отключаются в настройках. Открытое окно показывает то же
//! своими сообщениями, поэтому уведомление тогда не нужно.
//!
//! Тост показывается от имени `dev.kvt.client`: имя и значок для него
//! регистрируются в HKCU (`AppUserModelId`) — так Windows показывает «KVT», а не
//! PowerShell. Клик по уведомлению открывает окно на нужной странице; работает,
//! пока KVT запущен (а он в трее всегда).

use crate::{watchdog, AppState};
use kvt_core::i18n::tr;
use kvt_core::trf;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Listener, Manager};

pub const APP_ID: &str = "dev.kvt.client";
/// Окно перечитывает `take_notices`.
pub const NOTICES_EVENT: &str = "notices";

pub struct Notice {
    pub title: String,
    pub body: String,
    /// Страница окна по клику (`tray::open_page`); `None` — главная.
    pub page: Option<String>,
    /// Показать даже при открытом окне и выключенных уведомлениях (выход из KVT).
    pub force: bool,
}

/// Окно на экране: тогда сообщение видно в нём самом.
fn window_visible(app: &AppHandle) -> bool {
    app.get_webview_window("main")
        .is_some_and(|w| w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false))
}

fn enabled(app: &AppHandle) -> bool {
    app.state::<AppState>()
        .choice
        .lock()
        .map(|c| c.notifications)
        .unwrap_or(true)
}

/// Показывает уведомление, если окно закрыто и уведомления включены.
/// Возвращает, показано ли оно.
pub fn show(app: &AppHandle, notice: Notice) -> bool {
    if !notice.force && (window_visible(app) || !enabled(app)) {
        return false;
    }
    let handle = app.clone();
    let page = notice.page.clone();
    let toast = tauri_winrt_notification::Toast::new(APP_ID)
        .title(&notice.title)
        .text1(&notice.body)
        .sound(None)
        .on_activated(move |_| {
            match page.as_deref() {
                Some(p) => crate::tray::open_page(&handle, p),
                None => crate::tray::show_main_window(&handle),
            }
            Ok(())
        });
    match toast.show() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "уведомление Windows не показалось");
            false
        }
    }
}

/// Ошибка действия из трея: уведомлением, а если его не показать — в окне.
pub fn error(app: &AppHandle, message: &str) {
    let shown = show(
        app,
        Notice {
            title: "KVT".into(),
            body: message.to_owned(),
            page: None,
            force: false,
        },
    );
    if shown {
        return;
    }
    if let Ok(mut n) = app.state::<AppState>().notices.lock() {
        n.push(message.to_owned());
    }
    let _ = app.emit(NOTICES_EVENT, ());
    crate::tray::show_main_window(app);
}

/// Статус службы сменился (трей замечает это при опросе): обрыв соединения.
pub fn status_changed(app: &AppHandle, before: &str, failed_reason: Option<&str>) {
    let Some(reason) = failed_reason else {
        return;
    };
    if !matches!(before, "connected" | "zapret") {
        return;
    }
    show(
        app,
        Notice {
            title: if reason.to_lowercase().contains("kill switch") {
                tr(
                    "Соединение прервано — интернет закрыт",
                    "Connection lost — internet blocked",
                )
                .into()
            } else {
                tr("Соединение прервано", "Connection lost").into()
            },
            body: reason.to_owned(),
            page: Some("why".into()),
            force: false,
        },
    );
}

/// Текст события автопереключения (как `watchdogText` в окне).
fn watchdog_notice(event: &Value) -> Option<Notice> {
    let s = |k: &str| event.get(k).and_then(Value::as_str).unwrap_or_default();
    let (title, body, page) = match s("kind") {
        "switched" => (
            tr("Сервер заменён", "Server switched"),
            trf!(
                "Через «{}» перестали идти данные — KVT переключился на «{}».",
                "Data stopped going through “{}” — KVT switched to “{}”.",
                s("from"),
                s("to")
            ),
            None,
        ),
        "no_alternative" => (
            tr("Сервер не отвечает", "Server not responding"),
            trf!(
                "Через «{}» перестали идти данные, а рабочей замены в подписках нет.",
                "Data stopped going through “{}”, and there's no working replacement in your subscriptions.",
                s("server")
            ),
            Some("why"),
        ),
        "gave_up" => (
            tr("Автопереключение приостановлено", "Auto-switch paused"),
            tr(
                "Серверы слишком часто перестают работать — KVT не будет менять их полчаса.",
                "Servers fail too often — KVT won't switch them for half an hour.",
            )
            .to_owned(),
            Some("why"),
        ),
        "captive_portal" => (
            tr("Сеть просит войти", "The network asks you to sign in"),
            tr(
                "Как Wi-Fi в гостинице или кафе: отключите VPN, войдите в сеть и подключитесь снова.",
                "Like hotel or café Wi-Fi: disconnect the VPN, sign in to the network and connect again.",
            )
            .to_owned(),
            None,
        ),
        "server_replaced" => (
            tr("Сервер заменён", "Server switched"),
            trf!(
                "Сервера «{}» больше нет в подписке — KVT переключился на «{}».",
                "Server “{}” is no longer in the subscription — KVT switched to “{}”.",
                s("from"),
                s("to")
            ),
            None,
        ),
        "server_removed" => (
            tr("VPN отключён", "VPN disconnected"),
            trf!(
                "Сервер «{}» больше не в подписках.",
                "Server “{}” is no longer in your subscriptions.",
                s("server")
            ),
            None,
        ),
        // «Пропала сеть» видно и без KVT — уведомлять не о чем.
        _ => return None,
    };
    Some(Notice {
        title: title.into(),
        body,
        page: page.map(str::to_owned),
        force: false,
    })
}

/// Текст события автопроверки zapret (как в окне).
fn zapret_notice(event: &Value) -> Option<Notice> {
    let n = |k: &str| event.get(k).and_then(Value::as_u64).unwrap_or_default();
    match event.get("kind").and_then(Value::as_str)? {
        "picked" => Some(Notice {
            title: tr("zapret: стратегия заменена", "zapret: strategy replaced").into(),
            body: trf!(
                "Прежняя перестала справляться — KVT подобрал {} ({} из {}).",
                "The previous one stopped working — KVT picked {} ({} of {}).",
                event
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                n("passed"),
                n("max")
            ),
            page: Some("zapret".into()),
            force: false,
        }),
        "unhealthy" => Some(Notice {
            title: tr("zapret перестал справляться", "zapret stopped working").into(),
            body: trf!(
                "Прошло {} из {} проверок. Откройте вкладку Zapret → «Почему не работает?».",
                "{} of {} checks passed. Open the Zapret tab → “Why isn't it working?”.",
                n("passed"),
                n("max")
            ),
            page: Some("zapret".into()),
            force: false,
        }),
        _ => None,
    }
}

/// Слушает события автопереключения и zapret; регистрирует имя для тостов.
pub fn spawn(app: &AppHandle) {
    register_app_id(app);
    let handle = app.clone();
    app.listen_any(watchdog::EVENT, move |e| {
        if let Some(notice) = serde_json::from_str::<Value>(e.payload())
            .ok()
            .as_ref()
            .and_then(watchdog_notice)
        {
            show(&handle, notice);
        }
    });
    let handle = app.clone();
    app.listen_any(crate::zapret::AUTO_EVENT, move |e| {
        if let Some(notice) = serde_json::from_str::<Value>(e.payload())
            .ok()
            .as_ref()
            .and_then(zapret_notice)
        {
            show(&handle, notice);
        }
    });
}

/// `HKCU\Software\Classes\AppUserModelId\dev.kvt.client`: имя и значок отправителя.
fn register_app_id(app: &AppHandle) {
    match app.path().app_local_data_dir() {
        Ok(dir) => register_app_id_in(&dir),
        Err(e) => tracing::warn!(error = %e, "нет папки для значка уведомлений"),
    }
}

fn register_app_id_in(dir: &std::path::Path) {
    let icon = dir.join("notify-icon.png");
    if std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::write(&icon, include_bytes!("../icons/128x128.png")))
        .is_err()
    {
        tracing::warn!("значок для уведомлений не сохранился");
    }
    let key = format!(r"Software\Classes\AppUserModelId\{APP_ID}");
    if let Err(e) = crate::winreg::set_string(&key, "DisplayName", "KVT")
        .and_then(|()| crate::winreg::set_string(&key, "IconUri", &icon.to_string_lossy()))
    {
        tracing::warn!(error = %e, "имя для уведомлений не зарегистрировалось");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn watchdog_events_become_notices() {
        let n = watchdog_notice(&json!({"kind": "switched", "from": "A", "to": "B"})).unwrap();
        assert!(n.body.contains("«A»") && n.body.contains("«B»"));
        assert!(watchdog_notice(&json!({"kind": "no_network"})).is_none());
        assert_eq!(
            watchdog_notice(&json!({"kind": "gave_up"}))
                .unwrap()
                .page
                .as_deref(),
            Some("why")
        );
    }

    /// Настоящее уведомление на этом компьютере:
    /// `cargo test -p kvt-app real_toast -- --ignored`.
    #[test]
    #[ignore = "показывает уведомление Windows"]
    fn real_toast() {
        register_app_id_in(&std::env::temp_dir().join("kvt-notify-test"));
        tauri_winrt_notification::Toast::new(APP_ID)
            .title("Сервер заменён")
            .text1("Через «A» перестали идти данные — KVT переключился на «B».")
            .sound(None)
            .show()
            .unwrap();
    }

    #[test]
    fn zapret_events_become_notices() {
        let n = zapret_notice(&json!({"kind": "unhealthy", "passed": 1, "max": 4})).unwrap();
        assert!(n.body.contains("1 из 4"));
        let n = zapret_notice(&json!({"kind": "picked", "title": "ALT4", "passed": 4, "max": 4}))
            .unwrap();
        assert!(n.body.contains("ALT4"));
    }
}
