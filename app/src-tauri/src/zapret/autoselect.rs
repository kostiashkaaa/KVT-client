//! Автоподбор стратегии: стратегии по очереди, каждая — проверкой целей; лучшая
//! запоминается для текущей сети.

use super::*;

// ── Автоподбор ──

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Progress {
    /// 0 — проверка без zapret, дальше — номер стратегии.
    index: usize,
    total: usize,
    title: String,
    score: Option<u32>,
    max: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tried {
    pub id: String,
    pub title: String,
    pub passed: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickResult {
    pub best: Option<String>,
    pub best_title: Option<String>,
    pub score: u32,
    pub max: u32,
    /// Сколько проверок проходит без zapret.
    pub baseline: u32,
    pub tested: usize,
    pub cancelled: bool,
    /// Все проверенные стратегии с результатом — для таблицы во вкладке Zapret.
    pub tried: Vec<Tried>,
}

/// Подбирает стратегию: сначала проверка без zapret, потом стратегии по порядку
/// Flowseal до первой, прошедшей все проверки. Итог запоминается для текущей сети.
#[tauri::command]
pub async fn zapret_autoselect(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<PickResult, String> {
    Ok(autoselect(&app, &state).await?)
}

pub(super) async fn autoselect(
    app: &AppHandle,
    state: &AppState,
) -> Result<PickResult, ZapretError> {
    let before = status().await?;
    if matches!(before, Some(ServiceStatus::Connected { .. })) {
        return Err(ZapretError::VpnConnected);
    }
    if before.is_none() {
        return Err(ZapretError::NoService);
    }
    if state.zapret_picking.swap(true, Ordering::SeqCst) {
        return Err(ZapretError::AlreadyPicking);
    }
    state.zapret_cancel.store(false, Ordering::SeqCst);
    let result = pick(app, state, before).await;
    state.zapret_picking.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
pub fn zapret_autoselect_cancel(state: State<'_, AppState>) {
    state.zapret_cancel.store(true, Ordering::SeqCst);
}

pub(super) async fn pick(
    app: &AppHandle,
    state: &AppState,
    before: Option<ServiceStatus>,
) -> Result<PickResult, ZapretError> {
    // Подбор идёт минутами и сам переключает службу. Если за это время пользователь
    // подключился, отключился или сменил режим, подбор не трогает его выбор.
    let epoch = state.epoch();
    let acted = || state.epoch() != epoch;
    let strategies = strategies().await?;
    if strategies.is_empty() {
        return Err(ZapretError::NoStrategies);
    }
    let choice = state
        .choice
        .lock()
        .map_err(|_| ZapretError::State)?
        .zapret
        .clone();
    let network = network_key(state);
    let total = strategies.len();
    let progress = |index: usize, title: String, score: Option<u32>| {
        let _ = app.emit(
            PROGRESS_EVENT,
            Progress {
                index,
                total,
                title,
                score,
                max: MAX_SCORE,
            },
        );
    };

    // Без zapret: если всё и так открывается, подбирать нечего.
    let _ = call(Request::Disconnect).await;
    progress(0, tr("Без zapret", "Without zapret").into(), None);
    let baseline = measure().await;
    progress(
        0,
        tr("Без zapret", "Without zapret").into(),
        Some(baseline.passed),
    );

    let mut best: Option<(Strategy, Check)> = None;
    let mut tried = Vec::new();
    let mut cancelled = false;
    if baseline.passed < MAX_SCORE {
        for (i, strategy) in strategies.iter().enumerate() {
            if state.zapret_cancel.load(Ordering::SeqCst) || acted() {
                cancelled = true;
                break;
            }
            progress(i + 1, strategy.title.clone(), None);
            let mut plan = choice.plan(network.as_deref());
            plan.strategy = strategy.id.clone();
            if call(Request::StartZapret(Box::new(plan))).await.is_err() {
                progress(i + 1, strategy.title.clone(), Some(0));
                tried.push(Tried {
                    id: strategy.id.clone(),
                    title: strategy.title.clone(),
                    passed: 0,
                });
                continue;
            }
            let check = measure().await;
            progress(i + 1, strategy.title.clone(), Some(check.passed));
            tried.push(Tried {
                id: strategy.id.clone(),
                title: strategy.title.clone(),
                passed: check.passed,
            });
            let full = check.passed == MAX_SCORE;
            if best.as_ref().is_none_or(|(_, b)| check.better_than(b)) {
                best = Some((strategy.clone(), check));
            }
            if full {
                break;
            }
        }
    }
    // Стратегия, которая не лучше, чем без zapret, не нужна.
    let best = best.filter(|(_, c)| c.passed > baseline.passed);
    if acted() {
        // Служба уже работает так, как решил пользователь, — не останавливаем её.
        crate::tray::refresh(app).await;
        return Err(ZapretError::Interrupted);
    }

    if let Some((strategy, _)) = &best {
        crate::update_choice(app, |c| {
            if let Some(key) = &network {
                c.zapret.by_network.insert(key.clone(), strategy.id.clone());
            }
            c.zapret.strategy = Some(strategy.id.clone());
        })?;
        let _ = app.emit(watchdog::CHOICE_EVENT, ());
    }

    // Возвращаем как было: zapret работал — запускаем его с новой стратегией.
    let restart = matches!(before, Some(ServiceStatus::Zapret { .. }));
    let _ = call(Request::Disconnect).await;
    if restart {
        let plan = state
            .choice
            .lock()
            .map_err(|_| ZapretError::State)?
            .zapret
            .plan(network.as_deref());
        let _ = call(Request::StartZapret(Box::new(plan))).await;
    }
    crate::tray::refresh(app).await;
    if let Some((strategy, check)) = &best {
        let record = CheckRecord {
            at: now_unix(),
            strategy: restart.then(|| strategy.id.clone()),
            check: check.clone(),
        };
        if let Ok(mut last) = state.zapret_last.lock() {
            *last = Some(record.clone());
        }
        let _ = app.emit(CHECK_EVENT, &record);
    }

    Ok(PickResult {
        best_title: best.as_ref().map(|(s, _)| s.title.clone()),
        score: best.as_ref().map_or(baseline.passed, |(_, c)| c.passed),
        best: best.map(|(s, _)| s.id),
        max: MAX_SCORE,
        baseline: baseline.passed,
        tested: tried.len(),
        cancelled,
        tried,
    })
}
