//! Действия пунктов меню: тем же путём, что окно, — `Choice` → settings.json →
//! `choice-changed` → переподключение, если подключение работает.

use super::*;

pub(super) fn on_menu(app: &AppHandle, id: &str) {
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
                match act(&app, &id).await {
                    // Подключение прервали «Отключить» — это не ошибка.
                    Err(message) if !kvt_core::ipc::is_cancelled(&message) => {
                        crate::notify::error(&app, &message)
                    }
                    _ => {}
                }
                invalidate(&app);
            });
        }
    }
}

/// Работает VPN, zapret, и держит ли kill switch интернет закрытым после сбоя
/// (по последнему статусу).
/// VPN подключён, работает только zapret, kill switch держит интернет закрытым
/// (или идёт подключение — тогда «Отключить» его отменяет).
pub(super) fn active(app: &AppHandle) -> (bool, bool, bool) {
    let status = app
        .try_state::<Tray>()
        .and_then(|t| t.status.lock().ok().and_then(|s| s.clone()));
    (
        matches!(status, Some(ServiceStatus::Connected { .. })),
        matches!(status, Some(ServiceStatus::Zapret { .. })),
        matches!(
            status,
            Some(ServiceStatus::Failed { blocked: true, .. } | ServiceStatus::Connecting)
        ),
    )
}

/// Меняет выбор, сохраняет и сообщает окну. Возвращает новый выбор.
pub(super) fn change(
    app: &AppHandle,
    f: impl FnOnce(&mut crate::Choice),
) -> Result<crate::Choice, String> {
    let choice = crate::update_choice(app, f)?;
    let _ = app.emit(watchdog::CHOICE_EVENT, ());
    Ok(choice)
}

pub(super) async fn reconnect(app: &AppHandle) -> Result<(), String> {
    connect_current(app, true).await.map(|_| ())
}

pub(super) async fn act(app: &AppHandle, id: &str) -> Result<(), String> {
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
                app.state::<AppState>().user_disconnected();
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
                return Err(trf!(
                    "Не обновилось подписок: {failed}. Откройте KVT — у подписки будет видна причина.",
                    "Subscriptions not updated: {failed}. Open KVT — the reason is shown on the subscription."
                ));
            }
        }
        "quit" => quit(app).await,
        _ => {}
    }
    Ok(())
}

/// Явный выход — отключаем VPN, чтобы ядро не осталось работать без интерфейса.
pub(super) async fn quit(app: &AppHandle) {
    let ks = app
        .state::<AppState>()
        .choice
        .lock()
        .map(|c| c.kill_switch)
        .unwrap_or(false);
    let (vpn, _, blocked) = active(app);
    app.state::<AppState>().user_disconnected();
    let _ = disconnect_service().await;
    if ks && (vpn || blocked) {
        crate::notify::show(
            app,
            crate::notify::Notice {
                title: tr("KVT закрыт", "KVT closed").into(),
                body: tr(
                    "VPN и kill switch выключены: интернет идёт напрямую.",
                    "VPN and kill switch are off: the internet goes direct.",
                )
                .into(),
                page: None,
                force: true,
            },
        );
    }
    app.exit(0);
}
