//! «Почему не работает?» — проверка по шагам от простого к сложному: сеть, служба,
//! подписка, сервер, туннель. Итог — один понятный вывод и, если можно,
//! действие одной кнопкой.
//!
//! Сбор фактов (`gather`) отделён от выводов (`conclude`): выводы покрыты тестами.
//! Сетевых запросов немного: TCP-пинг сервера без TLS, один запрос через туннель
//! или одна проба сервера через тестовое ядро (с лимитами NetGovernor).
//!
//! Состав: `types` — словарь, `gather` — сбор фактов, `conclude` — выводы; команда Tauri — здесь.

use crate::AppState;
use tauri::State;

mod conclude;
mod gather;
#[cfg(test)]
mod tests;
mod types;

pub use conclude::conclude;
use gather::gather;
pub use types::{Diagnosis, Facts, Fix, ProbeFact, Step, StepState, SubFacts, Tone};

#[tauri::command]
pub async fn troubleshoot(state: State<'_, AppState>) -> Result<Diagnosis, String> {
    let diagnosis = conclude(&gather(&state).await);
    tracing::info!(title = %diagnosis.title, "«Почему не работает?»");
    if let Ok(mut last) = state.last_diagnosis.lock() {
        *last = Some(diagnosis.clone());
    }
    Ok(diagnosis)
}
