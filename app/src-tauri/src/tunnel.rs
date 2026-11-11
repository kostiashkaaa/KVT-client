//! Честный статус: «сервер принял подключение» и «сайты открываются» — разные
//! состояния. После подключения KVT проверяет, что через туннель идут данные
//! (`health::check`), и если нет — окно показывает предупреждение, а не «Подключено».
//! Дальше состояние обновляет автопереключение (раз в минуту).

use crate::{health, AppState};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

pub const EVENT: &str = "tunnel-state";
/// Служба отвечает «подключено», когда интернет уже идёт через TUN (или через 2 с
/// после запуска ядра, если этого не видно); секунда — ядру на DNS и соединение с
/// сервером. Не успело — следующая попытка через `BETWEEN`.
pub const SETTLE: Duration = Duration::from_secs(1);
const ATTEMPTS: usize = 3;
const BETWEEN: Duration = Duration::from_secs(3);

/// Запоминает состояние и сообщает окну (`None` — не проверяли или VPN выключен).
pub fn set(app: &AppHandle, ok: Option<bool>) {
    let state = app.state::<AppState>();
    let changed = state
        .tunnel
        .lock()
        .map(|mut t| std::mem::replace(&mut *t, ok) != ok)
        .unwrap_or(false);
    if changed {
        if ok == Some(false) {
            tracing::warn!("сервер принял подключение, но данные через туннель не идут");
        }
        let _ = app.emit(EVENT, ok);
    }
}

/// Проверка после подключения: несколько попыток, первая — через пару секунд.
pub fn spawn_verify(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let epoch = state.epoch();
        tokio::time::sleep(SETTLE).await;
        let mut worked = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(BETWEEN).await;
            }
            if let Ok(trace) = health::check(&state.health).await {
                worked = Some(trace.ms);
                break;
            }
        }
        // Пока шла проверка, могли отключиться или переподключиться.
        if !matches!(
            crate::query_status().await,
            Ok(Some(kvt_core::ipc::ServiceStatus::Connected { .. }))
        ) {
            return;
        }
        set(&app, Some(worked.is_some()));
        match worked {
            Some(ms) => {
                if let Some(entry) = state.selected() {
                    crate::outcomes::worked(&state, &entry.key, ms);
                }
            }
            // Сбой уже подтверждён несколькими попытками: автопереключение берётся
            // за него сразу, а не на следующей минутной проверке.
            None if state.epoch() == epoch => {
                if let Ok(mut failed) = state.verify_failed.lock() {
                    *failed = Some(epoch);
                }
                state.watchdog_wake.notify_one();
            }
            None => {}
        }
    });
}

/// Состояние для окна, открытого заново.
#[tauri::command]
pub fn tunnel_state(state: State<'_, AppState>) -> Option<bool> {
    state.tunnel.lock().ok().and_then(|t| *t)
}
