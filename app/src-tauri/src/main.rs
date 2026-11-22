// Без консольного окна в релизной сборке.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod about;
mod applog;
mod atomic;
mod audit;
mod autostart;
mod catalog;
mod choice;
mod connection;
mod device;
mod diagexport;
mod diagnostics;
mod dnscheck;
mod dpapi;
mod errors;
mod fetch;
mod health;
mod journal;
mod lang;
mod mica;
mod migrate;
mod netinfo;
mod netprofile;
mod notify;
mod outcomes;
mod power;
mod prober;
mod qr;
mod service_client;
mod services;
mod settings;
mod sitecheck;
mod state;
mod store;
mod subs;
mod tgproxy;
mod tray;
mod troubleshoot;
mod tunnel;
mod updates;
mod view;
mod vpncheck;
mod watchdog;
mod winreg;
mod zapret;

use kvt_core::compile::DnsPlan;
use kvt_core::core_select::{select_core, CoreKind};
use kvt_core::governor::{NetGovernor, NetPolicy};
use kvt_core::ipc::{self, ConnectPlan, Request, Response, ServiceStatus, Session};
use kvt_core::model::{Security, Server};
use kvt_core::routing::presets::{self, RoutingSettings};
use kvt_core::subscription::SubscriptionMeta;
use kvt_core::tester::{self, Outcome, QuickResult};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, State};

// Состояние, выбор, данные окна и подключение — в своих модулях; остальные
// модули обращаются к ним как `crate::…`.
use choice::*;
use connection::*;
use state::*;
use view::*;

/// Для мест без `AppHandle` под рукой (статус службы спрашивают отовсюду).
static APP: std::sync::OnceLock<AppHandle> = std::sync::OnceLock::new();

/// Первый запуск установленного KVT включает автозапуск («включён после установки»).
/// Установщик этого не делает: он работает от администратора, и `HKCU` у него может
/// оказаться чужим. Сборка для разработки автозапуск не трогает.
fn enable_autostart_once(app: &AppHandle) {
    if !autostart::installed() {
        return;
    }
    let state = app.state::<AppState>();
    let Ok(mut choice) = state.choice.lock() else {
        return;
    };
    if choice.autostart_offered {
        return;
    }
    if let Err(e) = autostart::set_autostart(true) {
        tracing::warn!(error = %e, "автозапуск не включился");
        return;
    }
    choice.autostart_offered = true;
    let _ = save_choice(app, &choice);
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
            let _ = APP.set(app.handle().clone());
            if let Ok(dir) = app.path().app_local_data_dir() {
                applog::init(&dir.join("logs"));
            }
            // Язык системы — пока не прочитан выбор: им написаны сообщения о файле настроек.
            kvt_core::i18n::set(lang::system());
            let loaded = load_choice(app.handle());
            let state = app.state::<AppState>();
            lang::apply(loaded.choice.language);
            if let Ok(mut c) = state.choice.lock() {
                *c = loaded.choice;
            }
            if let (Some(notice), Ok(mut n)) = (loaded.notice, state.notices.lock()) {
                n.push(notice);
            }
            let store = subs::load(app.handle())?;
            if let Ok(mut s) = state.store.lock() {
                *s = Some(store);
            }
            subs::rebuild(&state)?;
            outcomes::load(&state);
            migrate_choice(app.handle(), &state);
            subs::spawn_updater(app.handle().clone());
            tray::create(app.handle())?;
            notify::spawn(app.handle());
            updates::spawn(app.handle().clone());
            // Автозапуск (`--tray`) — сразу в трей; обычный запуск открывает окно.
            if autostart::started_in_tray() {
                tracing::info!("запуск из автозагрузки Windows — окно не открываем");
            } else {
                tray::show_main_window(app.handle());
            }
            spawn_connect_on_start(app.handle().clone());
            enable_autostart_once(app.handle());
            netprofile::spawn(app.handle().clone());
            watchdog::spawn(app.handle().clone());
            zapret::spawn_watch(app.handle().clone());
            power::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            subs::add_input,
            qr::qr_decode,
            subs::rename_subscription,
            subs::refresh_all_subscriptions,
            subs::open_subscription_link,
            subs::list_subscriptions,
            subs::remove_subscription,
            subs::remove_server,
            subs::edit_server,
            subs::refresh_subscription,
            subs::set_subscription_options,
            quick_check,
            prober::full_check,
            connect,
            disconnect,
            service_status,
            service_session,
            leak_test,
            snapshot,
            set_choice,
            list_catalog,
            check_route_target,
            dns_catalog,
            dnscheck::dns_check,
            troubleshoot::troubleshoot,
            sitecheck::site_check,
            vpncheck::vpn_check,
            services::services_last,
            services::services_check,
            services::services_pick,
            netprofile::current_network,
            zapret::zapret_strategies,
            tgproxy::tg_proxy_status,
            tgproxy::tg_proxy_open,
            tgproxy::tg_proxy_link,
            zapret::zapret_conflicts,
            zapret::zapret_stop_conflicts,
            zapret::zapret_autoselect,
            zapret::zapret_autoselect_cancel,
            zapret::zapret_info,
            zapret::zapret_latest,
            zapret::zapret_update,
            zapret::zapret_repair,
            zapret::zapret_check,
            zapret::zapret_last,
            zapret::zapret_diagnose,
            journal::net_log,
            journal::net_log_clear,
            audit::pc_audit,
            audit::pc_audit_fix,
            migrate::migrate_scan,
            migrate::migrate_pick_folder,
            migrate::migrate_import,
            take_notices,
            tray::take_page,
            tray::panel_snapshot,
            tray::panel_act,
            tray::panel_ready,
            tray::panel_close,
            tray::panel_open,
            autostart::autostart_state,
            autostart::set_autostart,
            about::about_info,
            about::open_link,
            updates::update_status,
            updates::update_check,
            about::start_service,
            service_client::service_mismatch,
            tunnel::tunnel_state,
            diagexport::diag_preview,
            diagexport::diag_save,
            lang::get_language,
            lang::set_language
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "KVT не смог запуститься");
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
