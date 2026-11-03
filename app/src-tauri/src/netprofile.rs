//! Профили сетей: что делать при подключении к знакомой сети. Например, дома —
//! режим «Гибрид» и автоподключение, в офисе — отключать VPN.
//!
//! Сеть проверяется раз в 10 секунд — это локальный вызов WinAPI без сетевых
//! запросов (`netinfo::current`).

use crate::netinfo::{self, Network};
use crate::{connect_current, disconnect_service, query_status, save_choice, watchdog, AppState};
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

async fn on_join(app: &AppHandle) {
    let state = app.state::<AppState>();
    let connected = matches!(
        query_status().await,
        Ok(Some(ServiceStatus::Connected { .. }))
    );
    let plan = plan(view(&state).profile.as_ref(), connected);
    if let Some(mode) = plan.mode {
        let choice = state.choice.lock().ok().map(|mut c| {
            c.mode = Some(mode);
            c.clone()
        });
        if let Some(choice) = choice {
            let _ = save_choice(app, &choice);
            let _ = app.emit(watchdog::CHOICE_EVENT, ());
        }
    }
    if plan.connect {
        let _ = connect_current(&state).await;
    } else if plan.disconnect {
        let _ = disconnect_service().await;
    }
    if plan.connect || plan.disconnect {
        crate::tray::refresh(app).await;
    }
}

pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last_key: Option<String> = None;
        let mut first = true;
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
                if network.is_some() {
                    on_join(&app).await;
                }
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
