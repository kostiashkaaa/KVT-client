//! Ошибки zapret в службе: комплект, списки, драйвер, обновление из релиза Flowseal,
//! запуск winws. Текст — в `Display` (на языке окна); окну уходит строкой в
//! `Response::Error` / `Failed` (handler.rs).

use crate::dirs::DirError;
use crate::supervisor::ProcessError;
use kvt_core::i18n::tr;
use kvt_core::trf;

#[derive(Debug, thiserror::Error)]
pub enum ZapretError {
    #[error("{}", trf!("нет файла {}", "file {} is missing", .0))]
    FileMissing(String),
    /// SHA-256 файла не из списка известных версий Flowseal.
    #[error("{}", trf!("файл {} изменён", "file {} was modified", .0))]
    FileModified(String),
    #[error("{}", tr("нет списков", "no lists"))]
    NoLists,
    #[error("{}", tr("нет ни одной стратегии", "no strategies"))]
    NoStrategies,
    /// Перед запуском winws: файлы комплекта не прошли проверку.
    #[error("{}", trf!(
        "Файлы zapret повреждены ({}). Нажмите «Переустановить» во вкладке Zapret или запустите scripts\\fetch-zapret.ps1",
        "zapret files are damaged ({}). Press “Reinstall” on the Zapret tab or run scripts\\fetch-zapret.ps1",
        .0
    ))]
    Damaged(Box<ZapretError>),
    #[error("{}", trf!("неизвестная стратегия «{}»", "unknown strategy “{}”", .0))]
    UnknownStrategy(String),
    #[error("{}", trf!(
        "стратегии «{}» нет в комплекте zapret",
        "strategy “{}” isn't in the zapret bundle",
        .0
    ))]
    StrategyMissing(String),
    #[error(
        "{}",
        tr(
            "в комплекте нет полного IP-списка (ipset-all.txt.backup)",
            "the bundle has no full IP list (ipset-all.txt.backup)",
        )
    )]
    NoFullIpset,
    /// Свои списки (`*-user.txt`) не собрались из доменов и адресов.
    #[error(transparent)]
    Lists(#[from] kvt_core::zapret::ZapretError),
    /// Список не записался: имя файла и причина.
    #[error("{}", trf!("список {}: {}", "list {}: {}", .0, .1))]
    List(String, String),
    #[error("{}", tr("им пользуется другая программа", "another app is using it"))]
    DriverInUse,
    /// Файловая операция или вызов Windows; текст — от системы, без секретов.
    #[error("{0}")]
    Io(String),
    /// tar.exe не запустился.
    #[error("tar: {0}")]
    Unpack(String),
    #[error(
        "{}",
        tr("не удалось распаковать архив", "couldn't unpack the archive")
    )]
    UnpackFailed,
    #[error("{}", trf!(
        "не удалось скачать Flowseal с GitHub: {}",
        "couldn't download Flowseal from GitHub: {}",
        .0
    ))]
    Download(String),
    #[error(
        "{}",
        tr(
            "архив не совпал с хэшем — загрузка отменена",
            "the archive didn't match its hash — download cancelled",
        )
    )]
    HashMismatch,
    #[error("{}", trf!(
        "не удалось узнать последнюю версию Flowseal на GitHub: {}",
        "couldn't get the latest Flowseal version from GitHub: {}",
        .0
    ))]
    Version(String),
    /// Ответ GitHub о релизе Flowseal не разобран; текст — от `parse_release`.
    #[error(transparent)]
    Release(#[from] kvt_core::zapret::ReleaseError),
    /// Новый комплект собран, но не прошёл ту же проверку, что и при запуске.
    #[error("{}", trf!(
        "новый комплект не прошёл проверку: {}",
        "the new bundle failed verification: {}",
        .0
    ))]
    Rejected(Box<ZapretError>),
    /// Работа в отдельном потоке оборвалась (паника).
    #[error(
        "{}",
        tr(
            "Операция с zapret прервалась. Повторите; если не выйдет — сохраните диагностику.",
            "The zapret operation was interrupted. Try again; if it fails, save diagnostics.",
        )
    )]
    Interrupted,
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error(transparent)]
    Process(#[from] ProcessError),
}

impl ZapretError {
    /// Для `map_err` у файловых операций и вызовов Windows.
    pub fn io(e: impl std::fmt::Display) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_errors_keep_the_cause() {
        let e = ZapretError::Damaged(Box::new(ZapretError::FileModified("winws.exe".into())));
        assert!(e.to_string().contains("winws.exe"), "{e}");
        let e = ZapretError::Rejected(Box::new(ZapretError::NoLists));
        assert!(
            e.to_string().contains(&ZapretError::NoLists.to_string()),
            "{e}"
        );
    }
}
