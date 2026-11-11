//! Профили сетей: что делать при подключении к знакомой сети. Например, дома —
//! режим «Гибрид» и автоподключение, в офисе — отключать VPN.
//!
//! Сеть проверяется раз в 10 секунд — это локальный вызов WinAPI без сетевых
//! запросов (`netinfo::current`).

use crate::netinfo::{self, Network};
use crate::{connect_current, disconnect_service, query_status, watchdog, AppState};
use kvt_core::ipc::ServiceStatus;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

const POLL: Duration = Duration::from_secs(10);
pub const EVENT: &str = "network-changed";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnJoin {
    #[default]
    Nothing,
    Connect,
    Disconnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProfile {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub on_join: OnJoin,
    /// Режим, который включается в этой сети. `None` — не менять.
    #[serde(default)]
    pub mode: Option<String>,
}

/// Что нужно сделать при входе в сеть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub mode: Option<String>,
    pub connect: bool,
    pub disconnect: bool,
}

pub fn plan(profile: Option<&NetworkProfile>, connected: bool) -> Plan {
    let Some(p) = profile else {
        return Plan {
            mode: None,
            connect: false,
            disconnect: false,
        };
    };
    Plan {
        mode: p
            .mode
            .clone()
            .filter(|m| matches!(m.as_str(), "vpn" | "hybrid" | "zapret")),
        connect: p.on_join == OnJoin::Connect && !connected,
        disconnect: p.on_join == OnJoin::Disconnect && connected,
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkView {
    pub network: Option<Network>,
    pub profile: Option<NetworkProfile>,
}

fn view(state: &AppState) -> NetworkView {
    let network = state.network.lock().ok().and_then(|n| n.clone());
    let profile = network.as_ref().and_then(|n| {
        state
            .choice
            .lock()
            .ok()?
            .networks
            .iter()
            .find(|p| p.key == n.key)
            .cloned()
    });
    NetworkView { network, profile }
}

#[tauri::command]
pub fn current_network(state: State<'_, AppState>) -> NetworkView {
    view(&state)
}

/// Действия профиля при входе в сеть. `retry` — повтор, потому что служба в прошлый
/// раз ещё не отвечала. `switched` — компьютер перешёл из одной известной сети в
/// другую; запуск KVT и короткое «сети нет» (пока поднимается адаптер VPN) сменой не
/// считаются. Возвращает `false`, если профиль просит включить VPN, а
/// служба ещё не запустилась (после загрузки Windows она стартует с задержкой) —
/// тогда цикл повторит попытку.
async fn on_join(app: &AppHandle, retry: bool, switched: bool) -> bool {
    let state = app.state::<AppState>();
    let status = query_status().await.ok().flatten();
    // Работает VPN или только zapret — профилю есть что включать и выключать.
    let active = matches!(
        status,
        Some(ServiceStatus::Connected { .. } | ServiceStatus::Zapret { .. })
    );
    // Новая сеть — новая проверка zapret (стратегия могла перестать работать).
    if !retry {
        state.zapret_wake.notify_one();
    }
    let plan = plan(view(&state).profile.as_ref(), active);
    let network = crate::zapret::network_key(&state);
    let (old_mode, strategy) = state
        .choice
        .lock()
        .map(|c| {
            (
                c.mode.clone().unwrap_or_else(|| "vpn".into()),
                c.zapret.strategy_for(network.as_deref()),
            )
        })
        .unwrap_or_else(|_| ("vpn".into(), String::new()));
    let mode_changed = plan.mode.as_ref().is_some_and(|m| *m != old_mode);
    if let Some(mode) = plan.mode.filter(|_| mode_changed) {
        let _ = crate::update_choice(app, |c| c.mode = Some(mode));
        let _ = app.emit(watchdog::CHOICE_EVENT, ());
    }
    // В гибриде winws привязан к интерфейсу прежней сети, в режиме Zapret у новой
    // сети может быть своя подобранная стратегия, а другой режим требует перезапуска.
    let other_strategy = matches!(&status, Some(ServiceStatus::Zapret { strategy: running }) if *running != strategy);
    // Гибрид и стратегия zapret — только при настоящей смене сети: иначе каждый запуск
    // KVT в «Гибриде» переподключал VPN.
    let reconnect = active
        && !plan.disconnect
        && (mode_changed || (switched && (old_mode == "hybrid" || other_strategy)));
    if plan.connect && status.is_none() {
        // Режим уже применён, подключение — когда служба ответит.
        return false;
    }
    if plan.connect || reconnect || plan.disconnect {
        state.user_acted();
    }
    if plan.connect || reconnect {
        if reconnect {
            tracing::info!(
                hybrid = old_mode == "hybrid",
                mode_changed,
                other_strategy,
                "сеть сменилась — переподключение"
            );
        }
        let _ = connect_current(app, true).await;
    } else if plan.disconnect {
        let _ = disconnect_service().await;
    }
    if plan.connect || plan.disconnect || reconnect {
        crate::tray::refresh(app).await;
    }
    true
}

/// Сколько раз (раз в `POLL`) повторять «Включать VPN», пока служба не ответит:
/// 30 × 10 с — с запасом на отложенный автозапуск службы.
const JOIN_RETRIES: u32 = 30;

pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last_key: Option<String> = None;
        // Последняя сеть, которая была на самом деле (без промежутков «сети нет»).
        let mut last_known: Option<String> = None;
        let mut first = true;
        // Осталось повторов и счётчик действий пользователя, когда повтор назначили.
        let mut pending: Option<(u32, u64)> = None;
        loop {
            let key = tokio::task::spawn_blocking(netinfo::current)
                .await
                .ok()
                .flatten()
                .map(|n| n.key);
            if key != last_key || first {
                first = false;
                // Имя Wi-Fi (через netsh) запрашиваем только при смене сети.
                let network = match key {
                    Some(_) => tokio::task::spawn_blocking(netinfo::current_named)
                        .await
                        .ok()
                        .flatten(),
                    None => None,
                };
                last_key = network.as_ref().map(|n| n.key.clone());
                let state = app.state::<AppState>();
                if let Ok(mut n) = state.network.lock() {
                    n.clone_from(&network);
                }
                let _ = app.emit(EVENT, view(&state));
                pending = None;
                let switched = matches!(
                    (&last_known, &last_key),
                    (Some(old), Some(new)) if old != new
                );
                if last_key.is_some() {
                    last_known.clone_from(&last_key);
                }
                if network.is_some() && !on_join(&app, false, switched).await {
                    pending = Some((JOIN_RETRIES, state.epoch()));
                }
            } else if let Some((left, epoch)) = pending {
                let state = app.state::<AppState>();
                pending = if state.epoch() != epoch || left == 0 {
                    // Пользователь сам подключился или отключился — профиль не вмешивается.
                    None
                } else if on_join(&app, true, false).await {
                    None
                } else {
                    Some((left - 1, epoch))
                };
            }
            tokio::time::sleep(POLL).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(on_join: OnJoin, mode: Option<&str>) -> NetworkProfile {
        NetworkProfile {
            key: "k".into(),
            name: "Дом".into(),
            on_join,
            mode: mode.map(Into::into),
        }
    }

    #[test]
    fn unknown_network_changes_nothing() {
        let p = plan(None, false);
        assert_eq!(
            p,
            Plan {
                mode: None,
                connect: false,
                disconnect: false
            }
        );
    }

    #[test]
    fn connect_only_when_disconnected() {
        let home = profile(OnJoin::Connect, Some("hybrid"));
        assert!(plan(Some(&home), false).connect);
        assert!(!plan(Some(&home), true).connect);
        assert_eq!(plan(Some(&home), true).mode.as_deref(), Some("hybrid"));
    }

    #[test]
    fn trusted_network_disconnects() {
        let office = profile(OnJoin::Disconnect, None);
        assert!(plan(Some(&office), true).disconnect);
        assert!(!plan(Some(&office), false).disconnect);
    }

    #[test]
    fn unknown_mode_is_ignored() {
        let p = profile(OnJoin::Nothing, Some("rm -rf"));
        assert_eq!(plan(Some(&p), false).mode, None);
    }
}
