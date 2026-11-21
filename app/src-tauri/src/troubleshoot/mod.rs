//! «Почему не работает?» — проверка по шагам от простого к сложному: сеть, служба,
//! подписка, сервер, туннель. Итог — один понятный вывод и, если можно,
//! действие одной кнопкой.
//!
//! Сбор фактов (`gather`) отделён от выводов (`conclude`): выводы покрыты тестами.
//! Сетевых запросов немного: TCP-пинг сервера без TLS, один запрос через туннель
//! или одна проба сервера через тестовое ядро (с лимитами NetGovernor).
//!
//! Состав: `types` — словарь, `gather` — сбор фактов, `conclude` — выводы общего поиска
//! причины, `service` — выводы про сервис с плитки (✗ → «Почему?»); команда Tauri — здесь.

use crate::AppState;
use tauri::State;

mod conclude;
mod gather;
mod service;
#[cfg(test)]
mod tests;
mod types;

pub use conclude::conclude;
use gather::gather;
use service::conclude_for;
pub use types::{Diagnosis, Facts, Fix, ProbeFact, ServiceFact, Step, StepState, SubFacts, Tone};

/// Вывод по собранным фактам: про сервис, если спрашивали про него, иначе общий.
fn diagnose(f: &Facts) -> Diagnosis {
    match &f.focus {
        Some(service) => conclude_for(f, service),
        None => conclude(f),
    }
}

/// `service` — id сервиса с плитки (✗ → «Почему?»); без него — общий поиск причины.
/// Плитки не проверялись при нынешних условиях — тоже общий: про сервис сказать нечего.
#[tauri::command]
pub async fn troubleshoot(
    service: Option<String>,
    state: State<'_, AppState>,
) -> Result<Diagnosis, String> {
    let focus = match service {
        Some(id) => crate::services::fact(&state, &id).await,
        None => None,
    };
    let facts = gather(&state, focus).await;
    let diagnosis = diagnose(&facts);
    tracing::info!(
        title = %diagnosis.title,
        service = facts.focus.as_ref().map(|s| s.name.as_str()),
        "«Почему не работает?»"
    );
    if let Ok(mut last) = state.last_diagnosis.lock() {
        *last = Some(diagnosis.clone());
    }
    Ok(diagnosis)
}
