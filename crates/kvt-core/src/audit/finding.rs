//! Находка аудита и исправление к ней: [`Fix`] выполняет окно, [`ServiceFix`] — служба.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Утечки мимо VPN.
    Leaks,
    /// Программы, которые мешают VPN.
    Conflicts,
    /// Остатки других сборок zapret.
    Zapret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Ok,
    Info,
    Warning,
}

/// Исправление, которое выполняется по кнопке.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fix {
    /// Выключить системный прокси Windows (настройка пользователя).
    DisableSystemProxy,
    /// Закрыть программу пользователя.
    CloseProcess { pid: u32, name: String },
    /// Остановить чужие winws/GoodbyeDPI (`Request::StopConflicts`).
    StopZapret,
    /// Действие службы.
    Service(ServiceFix),
    /// Отключить запись автозагрузки пользователя (как «Отключить» в «Диспетчере задач»).
    DisableUserAutostart { id: String },
}

/// Исправления с правами администратора. Служба не верит параметрам на слово:
/// имя службы и запись автозагрузки должны найтись в её собственном сборе фактов
/// и подходить под признаки zapret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ServiceFix {
    /// `netsh winhttp reset proxy`.
    ResetWinHttpProxy,
    /// `netsh interface teredo set state disabled`.
    DisableTeredo,
    /// Остановить чужую службу zapret и перевести её в ручной запуск (не удаляя).
    DisableZapretService { name: String },
    /// Отключить запись автозагрузки для всех пользователей или задание планировщика.
    DisableAutostart { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub group: Group,
    pub level: Level,
    pub title: String,
    pub detail: String,
    pub fix: Option<Fix>,
}

impl Finding {
    pub(super) fn new(
        group: Group,
        level: Level,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            group,
            level,
            title: title.into(),
            detail: detail.into(),
            fix: None,
        }
    }

    pub(super) fn fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }
}
