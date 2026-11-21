//! Сервисы на вкладке «Проверка»: «работает ли то, что мне надо» (YouTube, Discord, Telegram,
//! Instagram, ChatGPT). Окно запрашивает каждый сервис по тому пути, по которому
//! пойдёт трафик пользователя, а плитки показывают итог и путь («VPN», «zapret»,
//! «напрямую»).
//!
//! Запросы идут через `NetGovernor` и пишутся в журнал, поэтому фонового опроса по
//! таймеру нет. Проверка — по действию: после подключения (VPN и zapret уже
//! встали), по кнопке и при открытии вкладки, если прошлый итог старше нескольких
//! минут. Пока ничего не подключено, сами KVT к этим сайтам не ходит: проба шла бы
//! мимо всего настроенного, и «не открывается» только напугало бы.
//!
//! Последний итог лежит в `AppState` — его читают окно и (позже) мини-панель из
//! трея. Данные, путь и вердикт — в `kvt_core::services` (с тестами), здесь сеть.
//!
//! Состав: здесь — итог и команды; `run` — когда и что проверять; `probe` — запрос.

use kvt_core::i18n::tr;
use kvt_core::ipc::ServiceStatus;
use kvt_core::routing::RoutingPlan;
use kvt_core::services::{Health, Via};
use serde::Serialize;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

mod probe;
mod run;

pub(crate) use run::{check, spawn_after_connect, Trigger};

/// Событие окну: итог изменился или проверка началась.
pub const EVENT: &str = "services";
/// Итог не старше этого при открытии вкладки не перепроверяется.
const FRESH_SECS: u64 = 5 * 60;

/// Что известно о сервисе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Ещё не проверяли.
    Unknown,
    /// NetGovernor не дал открыть соединение: слишком частые запросы к этому хосту.
    Waiting,
    Done(Health),
}

#[derive(Debug, Clone)]
struct Entry {
    id: String,
    name: String,
    via: Via,
    status: Status,
}

/// Последняя проверка. `key` — при каких условиях она сделана (запущено, режим,
/// прокси Telegram): при других условиях итог не показывается.
#[derive(Debug, Clone)]
struct Stored {
    key: String,
    at: u64,
    entries: Vec<Entry>,
}

/// С чем подключились. Выбор в окне меняется раньше, чем применяется (например,
/// правка маршрутизации ждёт «Применить»), поэтому путь сервиса считается по плану,
/// отправленному службе, а не по тому, что собрался бы из выбора сейчас.
#[derive(Clone)]
struct ConnectedWith {
    plan: RoutingPlan,
    hybrid: bool,
}

#[derive(Default)]
pub(crate) struct Cache {
    last: Mutex<Option<Stored>>,
    running: AtomicBool,
    connected: Mutex<Option<ConnectedWith>>,
}

impl Cache {
    /// Службе отправлен план (`send_plan`): прежний итог относился к другому
    /// подключению (сервер, режим и маршрутизация могли смениться при том же ключе
    /// условий), поэтому он сбрасывается, а план запоминается. `with` — план VPN и
    /// «Гибрид» ли; у режима «Zapret» плана нет.
    pub(crate) fn connected_with(&self, status: &ServiceStatus, with: Option<(RoutingPlan, bool)>) {
        if let Ok(mut last) = self.last.lock() {
            *last = None;
        }
        if let Ok(mut connected) = self.connected.lock() {
            *connected = match status {
                ServiceStatus::Connected { .. } => {
                    with.map(|(plan, hybrid)| ConnectedWith { plan, hybrid })
                }
                _ => None,
            };
        }
    }

    fn plan(&self) -> Option<ConnectedWith> {
        self.connected.lock().ok()?.clone()
    }

    fn stored(&self, key: &str) -> Option<Stored> {
        self.last
            .lock()
            .ok()?
            .as_ref()
            .filter(|s| s.key == key)
            .cloned()
    }

    fn store(&self, stored: Stored) {
        if let Ok(mut last) = self.last.lock() {
            *last = Some(stored);
        }
    }

    /// Итог при тех же условиях есть и не устарел. Итог «из будущего» (часы перевели
    /// назад) свежим не считается.
    fn fresh(&self, key: &str) -> bool {
        self.stored(key)
            .is_some_and(|s| now().checked_sub(s.at).is_some_and(|age| age < FRESH_SECS))
    }

    fn checking(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Плитка для окна. Текст — на языке окна на момент отправки.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Tile {
    pub id: String,
    pub name: String,
    pub via: Via,
    /// `unknown`, `waiting`, `works`, `slow` или `down`.
    pub state: &'static str,
    /// Что случилось; пусто, пока не проверяли.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Когда проверено (секунды Unix); `None` — не проверяли.
    pub at: Option<u64>,
    pub checking: bool,
    /// Что работает сейчас: `off`, `vpn`, `hybrid` или `zapret`.
    pub running: &'static str,
    pub tiles: Vec<Tile>,
}

impl Entry {
    fn tile(&self) -> Tile {
        let (state, detail) = match self.status {
            Status::Unknown => ("unknown", String::new()),
            Status::Waiting => (
                "waiting",
                tr(
                    "Слишком частые запросы к сайту — подождите минуту",
                    "Too many requests to the site — wait a minute",
                )
                .to_owned(),
            ),
            Status::Done(health) => (
                match health {
                    Health::Works => "works",
                    Health::Slow => "slow",
                    Health::Down(_) => "down",
                },
                health.message().to_owned(),
            ),
        };
        Tile {
            id: self.id.clone(),
            name: self.name.clone(),
            via: self.via,
            state,
            detail,
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Итог для окна: сохранённый, если он сделан при тех же условиях, иначе плитки
/// «не проверено».
#[tauri::command]
pub async fn services_last(state: tauri::State<'_, crate::AppState>) -> Result<Snapshot, String> {
    Ok(run::view(&state).await)
}

/// Проверить сервисы. `auto` — вкладка открылась: проверка нужна, только если итог
/// устарел. Без `auto` — кнопка «Проверить».
#[tauri::command]
pub async fn services_check(app: tauri::AppHandle, auto: bool) -> Result<Snapshot, String> {
    let trigger = if auto {
        Trigger::Opened
    } else {
        Trigger::Button
    };
    Ok(check(&app, trigger).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::services::Cause;

    fn entry(status: Status) -> Entry {
        Entry {
            id: "youtube".into(),
            name: "YouTube".into(),
            via: Via::Vpn,
            status,
        }
    }

    fn stored(key: &str, at: u64) -> Stored {
        Stored {
            key: key.into(),
            at,
            entries: vec![entry(Status::Done(Health::Works))],
        }
    }

    #[test]
    fn result_is_fresh_only_for_the_same_conditions_and_for_a_few_minutes() {
        let cache = Cache::default();
        assert!(!cache.fresh("vpn:Vpn:true"));
        cache.store(stored("vpn:Vpn:true", now()));
        assert!(cache.fresh("vpn:Vpn:true"));
        // Другой режим или другое подключение — это уже другой итог.
        assert!(!cache.fresh("hybrid:Hybrid:true"));
        assert!(cache.stored("hybrid:Hybrid:true").is_none());

        cache.store(stored("vpn:Vpn:true", now() - FRESH_SECS - 1));
        assert!(!cache.fresh("vpn:Vpn:true"));
        // Часы перевели назад: итог «из будущего» свежим не считается.
        cache.store(stored("vpn:Vpn:true", now() + 3600));
        assert!(!cache.fresh("vpn:Vpn:true"));
    }

    #[test]
    fn connecting_resets_the_result_and_remembers_the_plan_it_was_sent() {
        use kvt_core::core_select::CoreKind;
        use kvt_core::routing::Action;
        let cache = Cache::default();
        cache.store(stored("vpn:Vpn:true", now()));
        assert!(cache.fresh("vpn:Vpn:true"));

        // Подключились (например, другим сервером): прежний итог — про другое подключение,
        // а план запомнен, пока он идёт.
        let connected = ServiceStatus::Connected {
            core: CoreKind::Xray,
        };
        cache.connected_with(&connected, Some((RoutingPlan::new(Action::Direct), true)));
        assert!(!cache.fresh("vpn:Vpn:true"));
        assert!(cache.plan().is_some_and(|with| with.hybrid));

        // Режим «Zapret» и отключение плана не оставляют: путь считается без него.
        cache.connected_with(
            &ServiceStatus::Zapret {
                strategy: "general".into(),
            },
            None,
        );
        assert!(cache.plan().is_none());
        cache.connected_with(&connected, Some((RoutingPlan::new(Action::Proxy), false)));
        cache.connected_with(&ServiceStatus::Disconnected, None);
        assert!(cache.plan().is_none());
    }

    #[test]
    fn tiles_carry_state_and_text() {
        let tile = |status| entry(status).tile();
        assert_eq!(tile(Status::Unknown).state, "unknown");
        assert!(tile(Status::Unknown).detail.is_empty());
        assert_eq!(tile(Status::Waiting).state, "waiting");
        assert_eq!(tile(Status::Done(Health::Works)).state, "works");
        assert_eq!(tile(Status::Done(Health::Slow)).state, "slow");
        let down = tile(Status::Done(Health::Down(Cause::Cut)));
        assert_eq!(down.state, "down");
        assert!(!down.detail.is_empty());
    }

    #[test]
    fn tile_serializes_for_the_window() {
        let json = serde_json::to_value(entry(Status::Done(Health::Works)).tile()).unwrap();
        assert_eq!(json["via"], "vpn");
        assert_eq!(json["state"], "works");
        // Адресов и путей в плитке нет: окну нужны только данные для показа.
        assert!(json.get("url").is_none() && json.get("host").is_none());
    }
}
