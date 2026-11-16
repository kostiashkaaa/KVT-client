//! Стратегия Flowseal, её название и порядок в списке, ошибки разбора стратегий и файлов.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Порядок перебора при автоподборе — как в меню Flowseal: основная, ALT…, FAKE TLS, SIMPLE FAKE.
pub const PREFERRED_ORDER: &[&str] = &[
    "general",
    "general (ALT)",
    "general (ALT2)",
    "general (ALT3)",
    "general (ALT4)",
    "general (ALT6)",
    "general (ALT7)",
    "general (ALT8)",
    "general (ALT9)",
    "general (ALT10)",
    "general (ALT11)",
    "general (ALT12)",
    "general (ALT13)",
    "general (FAKE TLS AUTO)",
    "general (FAKE TLS AUTO ALT)",
    "general (FAKE TLS AUTO ALT2)",
    "general (FAKE TLS AUTO ALT3)",
    "general (SIMPLE FAKE)",
    "general (SIMPLE FAKE ALT)",
    "general (SIMPLE FAKE ALT2)",
    "general (EXP)",
    "general (ALT5)",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ZapretError {
    #[error(
        "{}",
        crate::i18n::tr(
            "в файле стратегии нет запуска winws.exe",
            "the strategy file doesn't run winws.exe"
        )
    )]
    NoWinws,
    #[error(
        "{}",
        crate::i18n::tr("незакрытая кавычка в аргументах", "unclosed quote in arguments")
    )]
    Quote,
    #[error("{}", crate::trf!("флаг «{}» не разрешён", "flag “{}” isn't allowed", .0))]
    Flag(String),
    #[error("{}", crate::trf!("недопустимое значение «{}» у флага {}", "invalid value “{}” for flag {}", .1, .0))]
    Value(String, String),
    #[error("{}", crate::trf!("неизвестная стратегия «{}»", "unknown strategy “{}”", .0))]
    UnknownStrategy(String),
    #[error("{}", crate::trf!("недопустимый домен «{}»", "invalid domain “{}”", .0))]
    Domain(String),
}

/// Стратегия: id — имя файла без `.bat` (`general (ALT4)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Strategy {
    pub id: String,
    pub title: String,
    /// Flowseal не рекомендует (пометка `NOT RECOMMENDED` в файле).
    pub recommended: bool,
    /// Использует `fooling=ts` — нужны включённые TCP timestamps.
    pub needs_timestamps: bool,
    /// Аргументы с подстановками `%BIN%`, `%LISTS%`, `%GameFilter…%`.
    #[serde(skip)]
    pub args: Vec<String>,
}

/// Название для интерфейса: `general` → «Основная», `general (ALT4)` → «ALT4».
pub fn title(id: &str) -> String {
    match id
        .strip_prefix("general (")
        .and_then(|s| s.strip_suffix(')'))
    {
        Some(inner) => inner.to_owned(),
        None if id == "general" => crate::i18n::tr("Основная", "Main").to_owned(),
        None => id.to_owned(),
    }
}

/// Безопасное имя стратегии: буквы, цифры, пробел, скобки — без путей.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '(' | ')' | '_' | '-'))
}

/// Сортировка для интерфейса и автоподбора: порядок Flowseal, неизвестные — в конце.
pub fn sort(strategies: &mut [Strategy]) {
    let rank = |id: &str| {
        PREFERRED_ORDER
            .iter()
            .position(|p| *p == id)
            .unwrap_or(PREFERRED_ORDER.len())
    };
    strategies.sort_by(|a, b| {
        (!a.recommended, rank(&a.id), &a.id).cmp(&(!b.recommended, rank(&b.id), &b.id))
    });
}
