//! Сон и пробуждение. После выхода из сна (`PBT_APMRESUMEAUTOMATIC`) туннель
//! проверяется сразу, а не через минуту автопереключения: соединения с сервером
//! за время сна обычно рвутся, а Wintun после гибернации бывает без маршрутов.
//! Если данные не идут — KVT переподключается к тому же серверу, а дальше, если
//! и это не помогло, работает обычное автопереключение.

#![allow(unsafe_code)]

use crate::{health, query_status, AppState};
use kvt_core::ipc::ServiceStatus;
use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Duration;
use tauri::{AppHandle, Manager};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use windows_sys::Win32::System::Power::{
    PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
};
use windows_sys::Win32::UI::WindowsAndMessaging::DEVICE_NOTIFY_CALLBACK;

/// Система вышла из сна (приходит всегда, даже без входа пользователя).
const PBT_APMRESUMEAUTOMATIC: u32 = 0x12;
/// Сеть после пробуждения поднимается не сразу.
const NETWORK_SETTLE: Duration = Duration::from_secs(5);

static RESUMED: OnceLock<UnboundedSender<()>> = OnceLock::new();

unsafe extern "system" fn on_power(
    _context: *const c_void,
    kind: u32,
    _setting: *const c_void,
) -> u32 {
    if kind == PBT_APMRESUMEAUTOMATIC {
        if let Some(tx) = RESUMED.get() {
            let _ = tx.send(());
        }
    }
    0
}

fn register() -> bool {
    // Параметры должны жить, пока жива подписка, — то есть всё время работы KVT.
    let params: &'static mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
        Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(on_power),
            Context: std::ptr::null_mut(),
        }));
    let mut handle: *mut c_void = std::ptr::null_mut();
    // SAFETY: params и handle — валидные указатели; params не освобождается.
    let rc = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            std::ptr::from_mut(params).cast(),
            &mut handle,
        )
    };
    rc == 0
}

pub fn spawn(app: AppHandle) {
    let (tx, mut rx) = unbounded_channel();
    if RESUMED.set(tx).is_err() || !register() {
        tracing::warn!("подписка на выход из сна не удалась");
        return;
    }
    tauri::async_runtime::spawn(async move {
        while rx.recv().await.is_some() {
            // Несколько событий подряд — одно пробуждение.
            while rx.try_recv().is_ok() {}
            tracing::info!("выход из сна");
            tokio::time::sleep(NETWORK_SETTLE).await;
            on_resume(&app).await;
        }
    });
}

async fn on_resume(app: &AppHandle) {
    if !matches!(
        query_status().await,
        Ok(Some(ServiceStatus::Connected { .. }))
    ) {
        return;
    }
    let state = app.state::<AppState>();
    if health::check(&state.health).await.is_ok() {
        crate::tunnel::set(app, Some(true));
        return;
    }
    tracing::info!("после сна данные не идут — переподключение");
    if let Err(e) = crate::connect_current(app, true).await {
        tracing::warn!(error = %e, "переподключение после сна не удалось");
    }
    crate::tray::refresh(app).await;
    // Если и это не помогло — автопереключение проверит и заменит сервер.
    state.watchdog_wake.notify_one();
}
