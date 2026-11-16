//! Ошибки подписок. Текст для пользователя — в `Display` (на двух языках, без
//! ссылок и токенов); команды окна отдают его строкой через `From`.

use crate::fetch::FetchError;
use kvt_core::i18n::tr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubsError {
    /// Подписка не загрузилась по ссылке.
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// Отравленный замок состояния (`errors::state_text`).
    #[error("{}", crate::errors::state_text())]
    State,
    #[error(
        "{}",
        tr(
            "хранилище подписок не загружено",
            "the subscription store isn't loaded"
        )
    )]
    NotLoaded,
    /// Файл подписок не записался; текст — от `errors::io` (что и почему).
    #[error("{0}")]
    Save(String),
    /// ID устройства нужен (режим «всегда»), а прочитать его не вышло; текст —
    /// от `errors::io`.
    #[error("{0}")]
    Device(String),
    #[error(
        "{}",
        tr(
            "В подписке не нашлось ни одного сервера.",
            "No servers found in the subscription."
        )
    )]
    NoServers,
    #[error(
        "{}",
        tr("Этой подписки уже нет.", "This subscription no longer exists.")
    )]
    Gone,
    #[error(
        "{}",
        tr(
            "У этой подписки нет ссылки для обновления",
            "This subscription has no update link",
        )
    )]
    NoLink,
}

impl From<SubsError> for String {
    fn from(e: SubsError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_error_keeps_its_text() {
        let e = SubsError::from(FetchError::Status(404));
        assert_eq!(e.to_string(), FetchError::Status(404).to_string());
        assert!(String::from(e).contains("404"));
    }
}
