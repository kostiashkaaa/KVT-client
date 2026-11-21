//! Когда и что проверять: что сейчас работает на самом деле, какие сервисы показать,
//! какие запросы разрешил `NetGovernor`.

use super::{now, probe, Cache, Entry, Pick, Snapshot, Status, Stored, EVENT};
use crate::connection::{build_plan, Plan};
use crate::{query_status, AppState};
use kvt_core::governor::Decision;
use kvt_core::ipc::ServiceStatus;
use kvt_core::netlog::{self, Origin, Purpose, Route};
use kvt_core::routing::RoutingPlan;
use kvt_core::services::{self, worst, Health, Mode, Running, ServiceDef};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

/// Что запустило проверку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// VPN или zapret только что встали.
    Connected,
    /// Открылась вкладка «Проверка».
    Opened,
    /// Кнопка «Проверить».
    Button,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Off,
    Vpn,
    Hybrid,
    Zapret,
}

/// Что работает на самом деле — не выбранный режим: пока не подключено или идёт
/// переподключение, трафик идёт мимо настроенного.
struct Active {
    kind: Kind,
    /// План, с которым подключились (VPN и «Гибрид»).
    plan: Option<RoutingPlan>,
    /// Прокси Telegram включён в настройках.
    telegram: bool,
    /// Выбранный режим: от него зависит набор сервисов.
    mode: Mode,
    /// Свой набор сервисов (`Choice.services`); `None` — по умолчанию для режима.
    picked: Option<Vec<String>>,
}

impl Active {
    fn running(&self) -> Running<'_> {
        match (self.kind, &self.plan) {
            (Kind::Vpn | Kind::Hybrid, Some(plan)) => Running::Vpn { plan },
            (Kind::Zapret, _) => Running::Zapret,
            _ => Running::Off,
        }
    }

    fn word(&self) -> &'static str {
        match self.kind {
            Kind::Off => "off",
            Kind::Vpn => "vpn",
            Kind::Hybrid => "hybrid",
            Kind::Zapret => "zapret",
        }
    }

    /// При каких условиях сделан итог: другой режим, другое подключение, прокси
    /// Telegram или набор сервисов — другие плитки и другие пути.
    fn key(&self) -> String {
        let shown: Vec<&str> = self.defs().iter().map(|d| d.id.as_str()).collect();
        format!(
            "{}:{:?}:{}:{}",
            self.word(),
            self.mode,
            self.telegram,
            shown.join(",")
        )
    }

    fn defs(&self) -> Vec<&'static ServiceDef> {
        services::select(self.mode, self.picked.as_deref())
    }

    fn entry(&self, def: &ServiceDef, status: Status) -> Entry {
        Entry {
            id: def.id.clone(),
            name: def.name.clone(),
            via: services::via(def, &self.running(), self.telegram),
            status,
        }
    }

    /// Все сервисы для выбора набора. Без своего набора отмечено всё: набор режима —
    /// это «все сервисы, что режим показывает», и сузить его в одном режиме значит
    /// сузить только то, что в нём видно, а не потерять остальное в других режимах.
    fn picks(&self) -> Vec<Pick> {
        services::all()
            .iter()
            .map(|def| Pick {
                id: def.id.clone(),
                name: def.name.clone(),
                chosen: self.picked.as_ref().is_none_or(|ids| ids.contains(&def.id)),
                offered: def.modes.contains(&self.mode),
            })
            .collect()
    }
}

async fn detect(state: &AppState) -> Active {
    let (mode, telegram, picked) = state
        .choice
        .lock()
        .map(|c| {
            (
                Mode::parse(c.mode.as_deref()),
                c.zapret.telegram,
                c.services.clone(),
            )
        })
        .unwrap_or((Mode::Vpn, false, None));
    let (kind, plan) = match query_status().await.ok().flatten() {
        Some(ServiceStatus::Connected { .. }) => match connected_plan(state) {
            Some((plan, hybrid)) => (if hybrid { Kind::Hybrid } else { Kind::Vpn }, Some(plan)),
            None => (Kind::Off, None),
        },
        Some(ServiceStatus::Zapret { .. }) => (Kind::Zapret, None),
        _ => (Kind::Off, None),
    };
    Active {
        kind,
        plan,
        telegram,
        mode,
        picked,
    }
}

/// План, с которым подключились. Окно перезапустили при работающем VPN — запомненного
/// плана нет, тогда лучшее, что есть, — план из сохранённого выбора.
fn connected_plan(state: &AppState) -> Option<(RoutingPlan, bool)> {
    if let Some(with) = state.services.plan() {
        return Some((with.plan, with.hybrid));
    }
    match build_plan(state) {
        Ok(Plan::Vpn(p)) => {
            let hybrid = p.zapret.is_some();
            Some((p.routing, hybrid))
        }
        _ => None,
    }
}

fn snapshot(state: &AppState, active: &Active) -> Snapshot {
    let (at, entries) = match state.services.stored(&active.key()) {
        Some(stored) => (Some(stored.at), stored.entries),
        None => (
            None,
            active
                .defs()
                .into_iter()
                .map(|def| active.entry(def, Status::Unknown))
                .collect(),
        ),
    };
    Snapshot {
        at,
        checking: state.services.checking(),
        running: active.word(),
        tiles: entries.iter().map(Entry::tile).collect(),
        picks: active.picks(),
        custom: active.picked.is_some(),
    }
}

pub(super) async fn view(state: &AppState) -> Snapshot {
    snapshot(state, &detect(state).await)
}

/// Только одна проверка за раз.
struct RunGuard<'a>(&'a AtomicBool);

impl<'a> RunGuard<'a> {
    fn take(cache: &'a Cache) -> Option<Self> {
        (!cache.running.swap(true, Ordering::SeqCst)).then_some(Self(&cache.running))
    }
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Проверка сервисов. Возвращает итог (новый или прежний, если проверять не нужно).
pub(crate) async fn check(app: &AppHandle, trigger: Trigger) -> Snapshot {
    let state = app.state::<AppState>();
    let active = detect(&state).await;
    let skip = match trigger {
        Trigger::Button => false,
        // Без VPN и zapret KVT сам к этим сайтам не ходит (см. шапку модуля).
        Trigger::Connected => active.kind == Kind::Off,
        Trigger::Opened => active.kind == Kind::Off || state.services.fresh(&active.key()),
    };
    if skip {
        return snapshot(&state, &active);
    }
    let Some(guard) = RunGuard::take(&state.services) else {
        return snapshot(&state, &active);
    };
    let _ = app.emit(EVENT, snapshot(&state, &active));
    let entries = probe_all(&state, &active).await;
    state.services.store(Stored {
        key: active.key(),
        at: now(),
        entries,
    });
    drop(guard);
    // Условия снимаем заново: пока шла проверка, выбор набора или режим могли смениться,
    // и событие со старыми отметками откатило бы их в окне.
    let done = snapshot(&state, &detect(&state).await);
    let _ = app.emit(EVENT, &done);
    done
}

/// Проверка после подключения: VPN или zapret уже встали. `settle` — пауза, чтобы
/// winws успел запуститься.
pub(crate) fn spawn_after_connect(app: AppHandle, settle: Duration) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(settle).await;
        let _ = check(&app, Trigger::Connected).await;
    });
}

/// NetGovernor разрешил открыть соединение к хосту (оно уже учтено). Иначе — запись
/// в журнале и «позже».
fn acquire(state: &AppState, host: &str) -> bool {
    let decision = match state.governor.lock() {
        Ok(mut governor) => governor.try_acquire(host, Instant::now()),
        Err(_) => return false,
    };
    if decision == Decision::Allowed {
        return true;
    }
    netlog::record_hold(
        Origin::App,
        Purpose::Service,
        host,
        Route::Direct,
        &decision,
    );
    false
}

async fn probe_all(state: &AppState, active: &Active) -> Vec<Entry> {
    let defs = active.defs();
    let previous = state.services.stored(&active.key());
    let client = probe::client().ok();
    let mut held = vec![false; defs.len()];
    let mut set = tokio::task::JoinSet::new();
    if let Some(client) = &client {
        for (i, def) in defs.iter().enumerate() {
            for p in &def.probes {
                if !acquire(state, &p.host) {
                    held[i] = true;
                    continue;
                }
                let (client, p) = (client.clone(), p.clone());
                set.spawn(async move {
                    let health = probe::run(&client, &p).await;
                    (i, p.host, health)
                });
            }
        }
    }
    let mut healths: Vec<Vec<Health>> = vec![Vec::new(); defs.len()];
    while let Some(done) = set.join_next().await {
        let Ok((i, host, health)) = done else {
            continue;
        };
        // Заморозка: хост не трогаем, пока не пройдёт пауза NetGovernor.
        if health.is_freeze() {
            if let Ok(mut governor) = state.governor.lock() {
                governor.report_freeze(&host, Instant::now());
            }
        }
        healths[i].push(health);
    }
    defs.iter()
        .enumerate()
        .map(|(i, def)| {
            let status = match worst(healths[i].iter().copied()) {
                Some(health) => Status::Done(health),
                // Не дали проверить: остаётся прошлый итог, а если его нет — «подождите».
                None if held[i] => previous
                    .as_ref()
                    .and_then(|s| s.entries.iter().find(|e| e.id == def.id))
                    .map(|e| e.status)
                    .filter(|status| matches!(status, Status::Done(_)))
                    .unwrap_or(Status::Waiting),
                None => Status::Unknown,
            };
            active.entry(def, status)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active(mode: Mode, picked: Option<&[&str]>) -> Active {
        Active {
            kind: Kind::Off,
            plan: None,
            telegram: false,
            mode,
            picked: picked.map(|ids| ids.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn state_of(picks: &[Pick], id: &str) -> (bool, bool) {
        let p = picks.iter().find(|p| p.id == id).unwrap();
        (p.chosen, p.offered)
    }

    #[test]
    fn without_an_own_set_everything_is_chosen_even_if_the_mode_hides_it() {
        // «Zapret»: Instagram и ChatGPT отмечены, но недоступны. Сузить набор здесь —
        // не потерять их в «VPN».
        let picks = active(Mode::Zapret, None).picks();
        assert_eq!(state_of(&picks, "instagram"), (true, false));
        assert_eq!(state_of(&picks, "youtube"), (true, true));
        assert!(picks.iter().all(|p| p.chosen));
        assert!(active(Mode::Vpn, None)
            .picks()
            .iter()
            .all(|p| p.chosen && p.offered));
    }

    #[test]
    fn own_set_marks_only_its_services() {
        let picks = active(Mode::Vpn, Some(&["youtube", "chatgpt"])).picks();
        let chosen: Vec<&str> = picks
            .iter()
            .filter(|p| p.chosen)
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(chosen, ["youtube", "chatgpt"]);
    }

    #[test]
    fn the_key_follows_the_shown_set() {
        let all = active(Mode::Vpn, None).key();
        assert_ne!(all, active(Mode::Vpn, Some(&["youtube"])).key());
        // Свой набор, который режиму ничего не оставил, — тот же набор, что по умолчанию.
        assert_eq!(
            active(Mode::Zapret, None).key(),
            active(Mode::Zapret, Some(&["instagram"])).key()
        );
    }
}
