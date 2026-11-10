//! Автопереключение: если через туннель перестали идти данные, KVT подключается к
//! следующему рабочему серверу подписки.
//!
//! Та же проверка обновляет честный статус (`tunnel`) — даже если автопереключение
//! выключено. Если данные не идут, а сеть просит войти (отель, кафе), сервер не
//! меняется: окно предлагает отключить VPN на время входа.
//!
//! Чтобы не создавать лишнего трафика, проверка — один маленький запрос раз в
//! минуту по уже открытому соединению. Сбой подтверждается ещё двумя попытками,
//! и только потом сервер считается нерабочим. Переключений не больше трёх за
//! полчаса: если не помогает, KVT сообщает об этом и больше не пытается.

use crate::catalog::Entry;
use crate::{connect_current, display_name, health, query_status, save_choice, AppState};
use kvt_core::ipc::{Captive, Request, Response, ServiceStatus};
use kvt_core::probe::Verdict;
use kvt_core::tester::{Outcome, QuickResult};
use kvt_core::Server;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

const INTERVAL: Duration = Duration::from_secs(60);
const RETRY_AFTER: Duration = Duration::from_secs(10);
const CONFIRMATIONS: usize = 2;
const MAX_INCIDENTS: usize = 3;
const INCIDENT_WINDOW: Duration = Duration::from_secs(30 * 60);
const CANDIDATES: usize = 3;

pub const EVENT: &str = "watchdog";
/// Выбор поменялся не из интерфейса (автопереключение, профиль сети).
pub const CHOICE_EVENT: &str = "choice-changed";

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Switched {
        from: String,
        to: String,
    },
    NoNetwork,
    NoAlternative {
        server: String,
    },
    GaveUp,
    /// Сеть просит войти (страница входа), а kill switch или туннель не дают её открыть.
    CaptivePortal,
    /// Сервер, к которому были подключены, исчез из подписок — VPN отключён.
    ServerRemoved {
        server: String,
    },
}

/// Просит ли сеть войти. Проверяет служба: ей kill switch не мешает.
pub(crate) async fn captive() -> Captive {
    match crate::service_client::call(Request::CaptiveCheck).await {
        Ok(Response::Captive { state }) => state,
        _ => Captive::Offline,
    }
}

/// Порядок замены среди `keys` (уже в порядке предпочтения подписок): сначала
/// проверенные полной проверкой (рабочие, затем медленные, по задержке), затем
/// отвечающие на TCP-пинг. Известно неработающие — исключаются.
pub(crate) fn rank(
    outcomes: &HashMap<String, Outcome>,
    quick: &HashMap<String, QuickResult>,
    keys: &[String],
) -> Vec<String> {
    let mut proven: Vec<(u8, u64, usize)> = Vec::new();
    let mut pinged: Vec<(u64, usize)> = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        match outcomes.get(key) {
            Some(Outcome::Checked {
                verdict: Verdict::Works,
                latency_ms,
            }) => proven.push((0, latency_ms.unwrap_or(u64::MAX), i)),
            Some(Outcome::Checked {
                verdict: Verdict::Slow,
                latency_ms,
            }) => proven.push((1, latency_ms.unwrap_or(u64::MAX), i)),
            Some(Outcome::Checked { .. }) => {}
            Some(Outcome::Deferred { .. }) | None => {
                if let Some(QuickResult::Reachable { latency_ms }) = quick.get(key) {
                    pinged.push((*latency_ms, i));
                }
            }
        }
    }
    proven.sort();
    pinged.sort();
    proven
        .into_iter()
        .map(|(_, _, i)| keys[i].clone())
        .chain(pinged.into_iter().map(|(_, i)| keys[i].clone()))
        .collect()
}

/// Кандидаты на замену текущему серверу: сначала из той же подписки, потом из
/// остальных. TCP-пинг (без TLS) — только если полной проверки не хватило.
pub(crate) async fn alternatives(state: &AppState, current: Option<&Entry>) -> Vec<String> {
    let entries = state.servers.lock().map(|s| s.clone()).unwrap_or_default();
    let outcomes = state.outcomes.lock().map(|o| o.clone()).unwrap_or_default();
    let others = |same: bool| -> Vec<&Entry> {
        entries
            .iter()
            .filter(|e| current.map_or(true, |c| c.key != e.key))
            .filter(|e| current.map_or(true, |c| (c.sub == e.sub) == same))
            .collect()
    };
    let tiers = if current.is_some() {
        vec![others(true), others(false)]
    } else {
        vec![others(true)]
    };

    let mut out = Vec::new();
    for tier in tiers {
        let keys: Vec<String> = tier.iter().map(|e| e.key.clone()).collect();
        let mut ranked = rank(&outcomes, &HashMap::new(), &keys);
        if out.len() + ranked.len() < CANDIDATES {
            let servers: Vec<Server> = tier.iter().map(|e| e.server.clone()).collect();
            // VPN подключён (иначе замена не нужна): пинг из приложения ушёл бы в TUN
            // и «ответил» бы за любой сервер. Пингует служба мимо туннеля; если она не
            // смогла — замена только среди проверенных полной проверкой.
            let results = match crate::ping_servers(&servers).await {
                Ok(results) => results,
                Err(e) => {
                    tracing::warn!(error = %e, "пинг кандидатов не удался");
                    Vec::new()
                }
            };
            let quick: HashMap<String, QuickResult> = keys.iter().cloned().zip(results).collect();
            ranked = rank(&outcomes, &quick, &keys);
        }
        out.extend(ranked);
        if out.len() >= CANDIDATES {
            break;
        }
    }
    out.truncate(CANDIDATES);
    out
}

pub(crate) fn server_name(state: &AppState, key: &str) -> String {
    state
        .entry(key)
        .map(|e| display_name(&e.server))
        .unwrap_or_else(|| "сервер".into())
}

/// Сбой подтверждён несколькими попытками подряд.
async fn tunnel_dead(client: &reqwest::Client) -> bool {
    if health::check(client).await.is_ok() {
        return false;
    }
    for _ in 0..CONFIRMATIONS {
        tokio::time::sleep(RETRY_AFTER).await;
        if health::check(client).await.is_ok() {
            return false;
        }
    }
    true
}

/// Подключается к серверу `key` и проверяет, что данные пошли.
pub(crate) async fn switch_to(app: &AppHandle, key: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    let choice = {
        let mut c = state.choice.lock().map_err(crate::errors::state)?;
        c.server = Some(key.to_owned());
        c.clone()
    };
    save_choice(app, &choice)?;
    let _ = app.emit(CHOICE_EVENT, ());
    connect_current(app, false).await?;
    crate::tray::refresh(app).await;
    // Ядру нужно несколько секунд, чтобы поднять TUN и маршруты.
    tokio::time::sleep(Duration::from_secs(3)).await;
    if tunnel_dead(&state.health).await {
        crate::tunnel::set(app, Some(false));
        return Err("через сервер не идут данные".into());
    }
    crate::tunnel::set(app, Some(true));
    Ok(())
}

/// `epoch` — счётчик действий пользователя на момент, когда сбой начали проверять.
/// Если пользователь с тех пор отключился или сам выбрал сервер, ничего не делаем.
async fn handle_incident(app: &AppHandle, epoch: u64) {
    let state = app.state::<AppState>();
    let stale = || state.epoch() != epoch;
    if tokio::task::spawn_blocking(crate::netinfo::current)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        let _ = app.emit(EVENT, Event::NoNetwork);
        return;
    }
    let current = state.selected();
    let from = current
        .as_ref()
        .map(|e| display_name(&e.server))
        .unwrap_or_default();
    let candidates = alternatives(&state, current.as_ref()).await;
    let tried = !candidates.is_empty();
    // Последний кандидат, через которого данные не пошли (он записан в выбор).
    let mut failed: Option<String> = None;
    for key in candidates {
        if stale() {
            tracing::info!(
                "пользователь сам подключился или отключился — автопереключение остановлено"
            );
            revert_failed(
                app,
                failed.as_deref(),
                current.as_ref().map(|e| e.key.as_str()),
            );
            return;
        }
        if switch_to(app, &key).await.is_ok() {
            if stale() {
                return;
            }
            let to = server_name(&state, &key);
            let _ = app.emit(EVENT, Event::Switched { from, to });
            return;
        }
        failed = Some(key);
    }
    // Замены не нашлось: возвращаем прежний сервер, иначе в окне остался бы выбран
    // последний неудачный кандидат, а уведомление говорило бы о другом.
    if stale() {
        revert_failed(
            app,
            failed.as_deref(),
            current.as_ref().map(|e| e.key.as_str()),
        );
        return;
    }
    if let (true, Some(original)) = (tried, current.as_ref()) {
        let _ = restore(app, &original.key).await;
    }
    let _ = app.emit(EVENT, Event::NoAlternative { server: from });
}

/// Пользователь вмешался, пока проверялся кандидат: подключаться не нужно, но
/// выбранным не должен остаться неудачный кандидат. Меняем выбор, только если
/// пользователь сам не выбрал другой сервер.
fn revert_failed(app: &AppHandle, failed: Option<&str>, original: Option<&str>) {
    let (Some(failed), Some(original)) = (failed, original) else {
        return;
    };
    let state = app.state::<AppState>();
    let choice = match state.choice.lock() {
        Ok(mut c) if c.server.as_deref() == Some(failed) => {
            c.server = Some(original.to_owned());
            c.clone()
        }
        _ => return,
    };
    if save_choice(app, &choice).is_ok() {
        let _ = app.emit(CHOICE_EVENT, ());
    }
}

/// Возвращает выбор на сервер `key` и подключается к нему без проверки туннеля.
async fn restore(app: &AppHandle, key: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    let choice = {
        let mut c = state.choice.lock().map_err(crate::errors::state)?;
        c.server = Some(key.to_owned());
        c.clone()
    };
    save_choice(app, &choice)?;
    let _ = app.emit(CHOICE_EVENT, ());
    let result = connect_current(app, true).await.map(|_| ());
    crate::tray::refresh(app).await;
    result
}

pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut incidents: VecDeque<Instant> = VecDeque::new();
        let mut gave_up = false;
        let mut portal_reported = false;
        loop {
            let state = app.state::<AppState>();
            // Выход из сна будит проверку раньше срока.
            tokio::select! {
                () = tokio::time::sleep(INTERVAL) => {}
                () = state.watchdog_wake.notified() => {}
            }
            let enabled = state.choice.lock().map(|c| c.auto_switch).unwrap_or(false);
            let connected = matches!(
                query_status().await,
                Ok(Some(ServiceStatus::Connected { .. }))
            );
            if !connected {
                gave_up = false;
                portal_reported = false;
                continue;
            }
            let epoch = state.epoch();
            if !tunnel_dead(&state.health).await {
                crate::tunnel::set(&app, Some(true));
                portal_reported = false;
                continue;
            }
            // Пока подтверждали сбой (около 20 с), пользователь мог нажать «Отключить»
            // или выбрать другой сервер — тогда это уже не наш сбой.
            if state.epoch() != epoch {
                continue;
            }
            crate::tunnel::set(&app, Some(false));
            // Сеть просит войти: другой сервер не поможет.
            if captive().await == Captive::Portal {
                if !portal_reported {
                    portal_reported = true;
                    tracing::info!("сеть просит войти — сервер не меняем");
                    let _ = app.emit(EVENT, Event::CaptivePortal);
                }
                continue;
            }
            if !enabled {
                continue;
            }
            while incidents
                .front()
                .is_some_and(|t| t.elapsed() > INCIDENT_WINDOW)
            {
                incidents.pop_front();
            }
            if incidents.len() >= MAX_INCIDENTS {
                if !gave_up {
                    gave_up = true;
                    let _ = app.emit(EVENT, Event::GaveUp);
                }
                continue;
            }
            incidents.push_back(Instant::now());
            handle_incident(&app, epoch).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked(verdict: Verdict, ms: u64) -> Outcome {
        Outcome::Checked {
            verdict,
            latency_ms: Some(ms),
        }
    }

    fn keys(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("k{i}")).collect()
    }

    #[test]
    fn proven_servers_first_then_pinged() {
        let outcomes: HashMap<String, Outcome> = [
            ("k0", checked(Verdict::Works, 300)),
            ("k1", checked(Verdict::DataFrozen, 100)),
            ("k3", checked(Verdict::Slow, 50)),
            ("k4", checked(Verdict::Works, 120)),
        ]
        .into_iter()
        .map(|(k, o)| (k.to_owned(), o))
        .collect();
        let quick: HashMap<String, QuickResult> = [
            ("k1", QuickResult::Reachable { latency_ms: 5 }),
            ("k2", QuickResult::Reachable { latency_ms: 80 }),
            ("k5", QuickResult::Reachable { latency_ms: 40 }),
        ]
        .into_iter()
        .map(|(k, q)| (k.to_owned(), q))
        .collect();
        // Замороженный k1 исключён, хоть и отвечает на пинг.
        assert_eq!(
            rank(&outcomes, &quick, &keys(6)),
            ["k4", "k0", "k3", "k5", "k2"]
        );
    }

    #[test]
    fn without_checks_uses_ping_only() {
        let quick: HashMap<String, QuickResult> = [
            ("k0", QuickResult::Unreachable),
            ("k1", QuickResult::Reachable { latency_ms: 90 }),
            ("k2", QuickResult::DnsFailed),
            ("k3", QuickResult::Reachable { latency_ms: 30 }),
        ]
        .into_iter()
        .map(|(k, q)| (k.to_owned(), q))
        .collect();
        assert_eq!(rank(&HashMap::new(), &quick, &keys(4)), ["k3", "k1"]);
        assert!(rank(&HashMap::new(), &HashMap::new(), &keys(4)).is_empty());
    }
}
