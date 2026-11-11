//! Журнал сетевых запросов для интерфейса: события приложения и службы вместе.

use crate::service_client;
use kvt_core::ipc::{Request, Response};
use kvt_core::netlog::{self, Event, HostSummary};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Окно сводки по хостам.
const SUMMARY_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Когда пользователь очистил журнал (мс). Журнал службы живёт до её перезапуска,
/// поэтому её записи старше этой отметки просто не показываются.
static CLEARED_AT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Journal {
    /// События от новых к старым.
    pub events: Vec<Event>,
    /// Сводка по хостам за последний час.
    pub hosts: Vec<HostSummary>,
    /// Служба ответила (иначе в журнале только запросы приложения).
    pub service: bool,
}

/// События приложения и службы, от новых к старым; записи службы до очистки
/// журнала (`cleared_at`) отбрасываются.
fn merge(mut app: Vec<Event>, service: Vec<Event>, cleared_at: u64) -> Vec<Event> {
    app.extend(service.into_iter().filter(|e| e.at > cleared_at));
    app.sort_by_key(|e| std::cmp::Reverse(e.at));
    app
}

#[tauri::command]
pub async fn net_log() -> Result<Journal, String> {
    let (service, from_service) = match service_client::call(Request::NetLog).await {
        Ok(Response::NetLog { events }) => (true, events),
        _ => (false, Vec::new()),
    };
    let events = merge(
        netlog::snapshot(),
        from_service,
        CLEARED_AT.load(Ordering::Relaxed),
    );
    let hosts = netlog::summarize(&events, netlog::now_ms(), SUMMARY_WINDOW);
    Ok(Journal {
        events,
        hosts,
        service,
    })
}

/// Очищает журнал приложения и скрывает записанное службой до этого момента.
#[tauri::command]
pub fn net_log_clear() {
    netlog::clear();
    CLEARED_AT.store(netlog::now_ms(), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::netlog::{Origin, Outcome, Purpose, Route};

    fn ev(at: u64, origin: Origin) -> Event {
        let mut e = Event::new(origin, Purpose::Rules, "a.com", Route::Direct, Outcome::Ok);
        e.at = at;
        e
    }

    #[test]
    fn merged_newest_first() {
        let merged = merge(
            vec![ev(1, Origin::App), ev(5, Origin::App)],
            vec![ev(3, Origin::Service)],
            0,
        );
        let order: Vec<u64> = merged.iter().map(|e| e.at).collect();
        assert_eq!(order, vec![5, 3, 1]);
    }

    #[test]
    fn service_events_before_clear_are_hidden() {
        let merged = merge(
            vec![ev(7, Origin::App)],
            vec![
                ev(3, Origin::Service),
                ev(5, Origin::Service),
                ev(6, Origin::Service),
            ],
            5,
        );
        let order: Vec<u64> = merged.iter().map(|e| e.at).collect();
        assert_eq!(order, vec![7, 6]);
    }
}
