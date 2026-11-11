//! Язык интерфейса: «Как в Windows», русский или английский. Выбор хранится в
//! settings.json (его читают и трей, и уведомления до открытия окна), а действующий
//! язык ставится в `kvt_core::i18n` — по нему же говорит служба (`Hello`).

#![allow(unsafe_code)]

use crate::AppState;
use kvt_core::i18n::{self, Lang};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LangChoice {
    #[default]
    Auto,
    Ru,
    En,
}

impl LangChoice {
    pub fn resolve(self) -> Lang {
        match self {
            LangChoice::Auto => system(),
            LangChoice::Ru => Lang::Ru,
            LangChoice::En => Lang::En,
        }
    }
}

/// Язык интерфейса Windows у текущего пользователя.
pub fn system() -> Lang {
    // SAFETY: функция без аргументов, только читает настройку пользователя.
    let langid = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
    Lang::from_langid(langid)
}

/// Поставить язык процесса по выбору пользователя.
pub fn apply(choice: LangChoice) {
    i18n::set(choice.resolve());
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LangInfo {
    choice: LangChoice,
    /// Действующий язык (для «Как в Windows» — язык системы).
    lang: Lang,
}

#[tauri::command]
pub fn get_language(state: State<'_, AppState>) -> LangInfo {
    let choice = state.choice.lock().map(|c| c.language).unwrap_or_default();
    LangInfo {
        choice,
        lang: i18n::current(),
    }
}

/// Выбор в «Настройках». Окно после ответа перезагружается на новом языке.
#[tauri::command]
pub fn set_language(choice: LangChoice, app: AppHandle) -> Result<LangInfo, String> {
    crate::update_choice(&app, |c| c.language = choice)?;
    apply(choice);
    if let Some(tray) = app.try_state::<crate::tray::Tray>() {
        tray.forget_texts();
    }
    crate::tray::invalidate(&app);
    Ok(LangInfo {
        choice,
        lang: i18n::current(),
    })
}
