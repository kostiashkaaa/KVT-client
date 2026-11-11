//! Итоги проверок серверов переживают перезапуск KVT. Без них автопереключение после
//! перезапуска выбирает замену только по TCP-пингу, а он не видит ни заморозку TLS,
//! ни отказ сервера. Хранятся сутки: условия у провайдера меняются.
//!
//! Плюс бесплатный сигнал: сервер, через который только что шли данные (проверка
//! туннеля после подключения и раз в минуту), считается рабочим — без отдельной
//! проверки и сетевых запросов.
//!
//! В файле — только ключи серверов (хэши) и вердикты, без адресов и ключей доступа.

use crate::AppState;
use kvt_core::probe::Verdict;
use kvt_core::tester::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::Manager;

const FILE: &str = "outcomes.json";
/// Сколько верим итогу проверки.
const TTL_SECS: u64 = 24 * 60 * 60;
/// «Данные шли» приходит раз в минуту — файл переписывается не чаще этого.
const WORKED_REFRESH_SECS: u64 = 30 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    latency_ms: Option<u64>,
    /// Когда проверен (секунды Unix).
    at: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path() -> Option<PathBuf> {
    crate::APP
        .get()?
        .path()
        .app_data_dir()
        .ok()
        .map(|d| d.join(FILE))
}

/// Свежие записи о серверах, которые есть в списке. Записи «из будущего» (часы
/// перевели назад) не берём: им нельзя верить.
fn fresh(
    saved: HashMap<String, Saved>,
    now: u64,
    known: impl Fn(&str) -> bool,
) -> HashMap<String, Saved> {
    saved
        .into_iter()
        .filter(|(key, s)| known(key) && s.at <= now && now - s.at < TTL_SECS)
        .collect()
}

/// Что записать после «данные шли через сервер». `None` — ничего не менять:
/// свежий итог «работает» или «медленно» уже есть. Медленный остаётся медленным —
/// проверка туннеля скорость не меряет, только освежает время.
fn worked_update(existing: Option<(&Outcome, u64)>, latency_ms: u64, now: u64) -> Option<Saved> {
    match existing {
        Some((
            Outcome::Checked {
                verdict,
                latency_ms: old,
            },
            at,
        )) if matches!(verdict, Verdict::Works | Verdict::Slow) => {
            (now.saturating_sub(at) >= WORKED_REFRESH_SECS).then_some(Saved {
                verdict: *verdict,
                latency_ms: *old,
                at: now,
            })
        }
        _ => Some(Saved {
            verdict: Verdict::Works,
            latency_ms: Some(latency_ms),
            at: now,
        }),
    }
}

/// Читает файл при запуске (после того как собран список серверов).
pub fn load(state: &AppState) {
    let Some(path) = path() else { return };
    let Some(saved) = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<HashMap<String, Saved>>(&b).ok())
    else {
        return;
    };
    let keys: Vec<String> = state
        .servers
        .lock()
        .map(|s| s.iter().map(|e| e.key.clone()).collect())
        .unwrap_or_default();
    let saved = fresh(saved, now(), |k| keys.iter().any(|key| key == k));
    let (Ok(mut outcomes), Ok(mut times)) = (state.outcomes.lock(), state.outcome_times.lock())
    else {
        return;
    };
    for (key, s) in saved {
        outcomes.entry(key.clone()).or_insert(Outcome::Checked {
            verdict: s.verdict,
            latency_ms: s.latency_ms,
        });
        times.entry(key).or_insert(s.at);
    }
}

/// Запоминает итоги проверок. «Отложено» — только в памяти, как раньше.
pub fn record(state: &AppState, items: impl IntoIterator<Item = (String, Outcome)>) {
    let at = now();
    {
        let (Ok(mut outcomes), Ok(mut times)) = (state.outcomes.lock(), state.outcome_times.lock())
        else {
            return;
        };
        for (key, outcome) in items {
            if matches!(outcome, Outcome::Checked { .. }) {
                times.insert(key.clone(), at);
            }
            outcomes.insert(key, outcome);
        }
    }
    save(state);
}

/// Через сервер `key` только что шли данные (`latency_ms` — время проверки туннеля).
pub fn worked(state: &AppState, key: &str, latency_ms: u64) {
    let at = now();
    {
        let (Ok(mut outcomes), Ok(mut times)) = (state.outcomes.lock(), state.outcome_times.lock())
        else {
            return;
        };
        let existing = outcomes
            .get(key)
            .map(|o| (o, times.get(key).copied().unwrap_or(0)));
        let Some(update) = worked_update(existing, latency_ms, at) else {
            return;
        };
        outcomes.insert(
            key.to_owned(),
            Outcome::Checked {
                verdict: update.verdict,
                latency_ms: update.latency_ms,
            },
        );
        times.insert(key.to_owned(), update.at);
    }
    save(state);
}

fn save(state: &AppState) {
    let Some(path) = path() else { return };
    let saved: HashMap<String, Saved> = {
        let (Ok(outcomes), Ok(times)) = (state.outcomes.lock(), state.outcome_times.lock()) else {
            return;
        };
        outcomes
            .iter()
            .filter_map(|(key, o)| match o {
                Outcome::Checked {
                    verdict,
                    latency_ms,
                } => Some((
                    key.clone(),
                    Saved {
                        verdict: *verdict,
                        latency_ms: *latency_ms,
                        at: *times.get(key)?,
                    },
                )),
                Outcome::Deferred { .. } => None,
            })
            .collect()
    };
    let Ok(bytes) = serde_json::to_vec(&saved) else {
        return;
    };
    // Пишут полная проверка, «Почему не работает?» и проверка туннеля — из разных потоков.
    static SAVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SAVE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, &path)) {
        tracing::warn!(error = %e, "итоги проверок серверов не сохранились");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(verdict: Verdict, at: u64) -> Saved {
        Saved {
            verdict,
            latency_ms: Some(100),
            at,
        }
    }

    #[test]
    fn only_fresh_known_entries_are_loaded() {
        let now = 10 * TTL_SECS;
        let file: HashMap<String, Saved> = [
            ("fresh", saved(Verdict::Works, now - 60)),
            ("old", saved(Verdict::Works, now - TTL_SECS)),
            ("future", saved(Verdict::Works, now + 60)),
            ("gone", saved(Verdict::Works, now - 60)),
        ]
        .into_iter()
        .map(|(k, s)| (k.to_owned(), s))
        .collect();
        let loaded = fresh(file, now, |k| k != "gone");
        assert_eq!(loaded.keys().collect::<Vec<_>>(), ["fresh"]);
    }

    #[test]
    fn file_format_survives_round_trip_and_bad_data() {
        let s = saved(Verdict::TlsFrozen, 5);
        let text = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Saved>(&text).unwrap(), s);
        assert!(serde_json::from_str::<HashMap<String, Saved>>(
            "{\"k\":{\"verdict\":\"???\",\"at\":1}}"
        )
        .is_err());
        assert!(serde_json::from_str::<HashMap<String, Saved>>("[1,2]").is_err());
    }

    #[test]
    fn worked_marks_unknown_and_failed_servers_as_working() {
        let now = 1_000_000;
        let new = worked_update(None, 80, now).unwrap();
        assert_eq!((new.verdict, new.latency_ms), (Verdict::Works, Some(80)));
        let frozen = Outcome::Checked {
            verdict: Verdict::DataFrozen,
            latency_ms: None,
        };
        let up = worked_update(Some((&frozen, now - 10)), 80, now).unwrap();
        assert_eq!(up.verdict, Verdict::Works);
    }

    #[test]
    fn worked_keeps_slow_and_rarely_rewrites() {
        let now = 1_000_000;
        let slow = Outcome::Checked {
            verdict: Verdict::Slow,
            latency_ms: Some(900),
        };
        assert!(worked_update(Some((&slow, now - 60)), 80, now).is_none());
        let up = worked_update(Some((&slow, now - WORKED_REFRESH_SECS)), 80, now).unwrap();
        assert_eq!(
            (up.verdict, up.latency_ms, up.at),
            (Verdict::Slow, Some(900), now)
        );
    }
}
