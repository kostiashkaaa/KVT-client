//! Ошибки подключения в окне. Текст для пользователя — в `Display`; командам окна
//! уходит строкой через `From`.

use crate::service_client::ServiceError;
use kvt_core::i18n::tr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConnectionError {
    /// Запрос до службы не дошёл или ответ не получен.
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// Служба ответила ошибкой (`Response::Error`); текст уже для пользователя.
    #[error("{0}")]
    Remote(String),
    /// Запуск прерван «Отключить» (служба) или пользователь вмешался (окно). Окно не
    /// показывает это как ошибку.
    #[error("{}", kvt_core::ipc::cancelled())]
    Cancelled,
    /// Ответ службы не тот, что ждали (`errors::unexpected`).
    #[error("{}", crate::errors::unexpected())]
    Unexpected,
    /// Отравленный замок состояния (`errors::state_text`).
    #[error("{}", crate::errors::state_text())]
    State,
    #[error(
        "{}",
        tr(
            "Выберите сервер в списке на главной.",
            "Pick a server from the list on the home page."
        )
    )]
    NoServer,
    #[error(
        "{}",
        tr(
            "Настройки маршрутизации противоречат друг другу — проверьте раздел «Маршрутизация».",
            "Routing settings contradict each other — check the “Routing” section.",
        )
    )]
    Routing,
    #[error(
        "{}",
        tr(
            "Выбранный DNS-сервер больше не поддерживается — выберите другой в настройках.",
            "The selected DNS server is no longer supported — pick another one in settings.",
        )
    )]
    Dns,
    /// Выбор (сервер, режим) не сохранился.
    #[error(transparent)]
    Settings(#[from] crate::settings::SettingsError),
    /// Подключились, но через сервер не идут данные (проверка туннеля).
    #[error(
        "{}",
        tr("через сервер не идут данные", "no data is going through the server")
    )]
    NoData,
    /// Служба не установлена или отключена: Windows не запустила её (`about::start_blocking`).
    #[error(transparent)]
    ServiceStart(#[from] crate::about::StartError),
}

impl ConnectionError {
    /// Ответ службы `Response::Error`: отмена — отдельным вариантом, остальное как есть.
    pub fn remote(message: String) -> Self {
        if kvt_core::ipc::is_cancelled(&message) {
            Self::Cancelled
        } else {
            Self::Remote(message)
        }
    }
}

impl From<ConnectionError> for String {
    fn from(e: ConnectionError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_from_the_service_is_recognised() {
        let cancelled = kvt_core::ipc::cancelled().to_owned();
        assert_eq!(
            ConnectionError::remote(cancelled),
            ConnectionError::Cancelled
        );
        assert_eq!(
            ConnectionError::remote("ядро упало".into()),
            ConnectionError::Remote("ядро упало".into())
        );
    }
}
