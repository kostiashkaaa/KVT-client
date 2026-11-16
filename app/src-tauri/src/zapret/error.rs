//! Ошибки zapret в окне. Текст для пользователя — в `Display` (на двух языках);
//! команды окна отдают его строкой через `From`.

use kvt_core::i18n::tr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ZapretError {
    /// Служба не ответила или ответила ошибкой; текст уже для пользователя.
    #[error("{0}")]
    Service(String),
    /// Служба ответила не тем (`errors::unexpected`: разные версии окна и службы).
    #[error("{}", crate::errors::unexpected())]
    Unexpected,
    #[error("{}", tr("Служба KVT не запущена.", "The KVT service isn't running."))]
    NoService,
    #[error(
        "{}",
        tr(
            "Отключите VPN: подбор проверяет сайты напрямую, через zapret.",
            "Disconnect the VPN: picking checks sites directly, through zapret.",
        )
    )]
    VpnConnected,
    /// Повторный «Подобрать», пока идёт подбор.
    #[error("{}", tr("Подбор уже идёт", "Picking is already running"))]
    AlreadyPicking,
    /// Проверка или обслуживание комплекта во время подбора.
    #[error(
        "{}",
        tr(
            "Идёт подбор стратегии — дождитесь его окончания",
            "A strategy is being picked — wait until it finishes",
        )
    )]
    Picking,
    #[error(
        "{}",
        tr(
            "Нет стратегий zapret. Нажмите «Переустановить» во вкладке Zapret.",
            "No zapret strategies. Press “Reinstall” on the Zapret tab.",
        )
    )]
    NoStrategies,
    /// Пользователь подключился, отключился или сменил режим во время подбора.
    #[error(
        "{}",
        tr(
            "Подбор прерван: подключение изменили во время проверки.",
            "Picking interrupted: the connection changed during the check.",
        )
    )]
    Interrupted,
    /// Последний релиз Flowseal не получен или не разобран; текст без адреса.
    #[error("{0}")]
    Release(String),
    /// Выбор (стратегия для сети) не сохранился; текст — от `update_choice`.
    #[error("{0}")]
    Settings(String),
    /// Отравленный замок или упавшая фоновая задача (`errors::state_text`).
    #[error("{}", crate::errors::state_text())]
    State,
}

impl From<ZapretError> for String {
    fn from(e: ZapretError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_text_is_passed_through() {
        let e = ZapretError::Service("winws не запустился".into());
        assert_eq!(String::from(e), "winws не запустился");
    }
}
