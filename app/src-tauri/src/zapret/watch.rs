//! Автопроверка: раз в полчаса, пока zapret работает; при сбое — подбор заново.

use super::*;

// ── Автопроверка ──

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum AutoEvent {
    /// Стратегия перестала работать, и KVT подобрал новую.
    Picked {
        title: String,
        passed: u32,
        max: u32,
    },
    /// Перестала работать, а подобрать не вышло (или автоподбор выключен, или гибрид).
    Unhealthy { passed: u32, max: u32 },
}

/// Раз в полчаса и после смены сети: открываются ли Discord и YouTube.
/// В режиме «Zapret» при сбое — автоподбор, если он разрешён.
pub fn spawn_watch(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            let state = app.state::<AppState>();
            let choice = state.choice.lock().map(|c| c.clone()).ok();
            let enabled = choice.as_ref().is_some_and(|c| c.zapret.auto_check);
            if enabled && !state.zapret_picking.load(Ordering::SeqCst) {
                if let Some(strategy) = running_strategy(&state).await {
                    let record = check_now(&app).await;
                    let zapret_only =
                        choice.as_ref().and_then(|c| c.mode.as_deref()) == Some("zapret");
                    let auto_pick = choice.as_ref().is_some_and(|c| c.zapret.auto_pick);
                    if !record.check.healthy() {
                        let picked = if zapret_only && auto_pick {
                            autoselect(&app, &state)
                                .await
                                .ok()
                                .filter(|r| r.best.is_some())
                        } else {
                            None
                        };
                        let event = match picked {
                            Some(r) => AutoEvent::Picked {
                                title: r.best_title.unwrap_or(strategy),
                                passed: r.score,
                                max: r.max,
                            },
                            None => AutoEvent::Unhealthy {
                                passed: record.check.passed,
                                max: record.check.max,
                            },
                        };
                        let _ = app.emit(AUTO_EVENT, event);
                    }
                }
            }
            // Смена сети будит раньше: дадим ей устояться.
            tokio::select! {
                _ = tokio::time::sleep(WATCH_INTERVAL) => {}
                _ = state.zapret_wake.notified() => {
                    tokio::time::sleep(Duration::from_secs(20)).await;
                }
            }
        }
    });
}
