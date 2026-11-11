//! Понятные тексты ошибок. Пользователь видит, что случилось и что делать, а
//! исходный технический текст (на английском, с кодами) уходит в журнал.

use kvt_core::i18n::tr;
use std::fmt::Display;

/// Замок состояния отравлен — значит, раньше в программе была паника (она уже в журнале).
pub fn state_text() -> &'static str {
    tr(
        "Внутренняя ошибка KVT. Перезапустите программу; если повторится — сохраните диагностику в разделе «Проверка».",
        "Internal KVT error. Restart the app; if it happens again, save diagnostics in the “Check” section.",
    )
}

/// Служба ответила не тем, что ждали: почти всегда это разные версии окна и службы.
pub fn unexpected() -> &'static str {
    tr(
        "Служба KVT ответила непонятно — похоже, окно и служба разных версий. Переустановите KVT.",
        "The KVT service gave an unexpected answer — the window and service seem to be different versions. Reinstall KVT.",
    )
}

/// Служба отвергла приветствие: окно и служба разных версий.
pub fn version_mismatch() -> &'static str {
    tr(
        "Окно KVT и служба разных версий — похоже, обновление прервалось. Установите KVT заново (полная установка со страницы загрузки): настройки и подписки сохранятся.",
        "The KVT window and service are different versions — the update seems to have been interrupted. Install KVT again (full installer from the download page): your settings and subscriptions will be kept.",
    )
}

/// Служба не запущена.
pub fn no_service() -> &'static str {
    tr(
        "Служба KVT не запущена, поэтому подключиться нельзя. Перезагрузите компьютер или переустановите KVT — служба запустится вместе с Windows.",
        "The KVT service isn't running, so you can't connect. Restart the computer or reinstall KVT — the service starts with Windows.",
    )
}

/// Для `map_err` у замков состояния.
pub fn state<T>(_: T) -> String {
    state_text().into()
}

/// Ошибка файла: что не получилось и почему.
pub fn io(what: &str, e: &std::io::Error) -> String {
    tracing::warn!(error = %e, "{what}");
    use std::io::ErrorKind as K;
    const ERROR_DISK_FULL: i32 = 112;
    let why = match e.kind() {
        K::PermissionDenied => tr(
            "нет доступа — возможно, файл открыт другой программой или его блокирует антивирус",
            "access denied — the file may be open in another app or blocked by antivirus",
        ),
        K::NotFound => tr("файл или папка не найдены", "file or folder not found"),
        _ if e.raw_os_error() == Some(ERROR_DISK_FULL) => {
            tr("на диске закончилось место", "the disk is full")
        }
        _ => tr("ошибка диска", "disk error"),
    };
    format!("{what}: {why}.")
}

/// Ошибка сети без адреса (в нём бывает токен подписки) и без технических подробностей.
pub fn net(e: &reqwest::Error) -> String {
    tracing::debug!(error = %e.to_string().split(" for url").next().unwrap_or_default(), "ошибка сети");
    if e.is_timeout() {
        tr("нет ответа", "no response").into()
    } else if e.is_connect() {
        tr("не удалось подключиться", "couldn't connect").into()
    } else if e.is_redirect() {
        tr("слишком много перенаправлений", "too many redirects").into()
    } else if e.is_body() || e.is_decode() {
        tr("соединение оборвалось", "the connection dropped").into()
    } else if e.is_status() {
        e.status()
            .map(|s| kvt_core::trf!("ошибка сервера {}", "server error {}", s.as_u16()))
            .unwrap_or_else(|| tr("ошибка сервера", "server error").into())
    } else {
        tr("ошибка сети", "network error").into()
    }
}

/// Записать в журнал и вернуть текст для пользователя.
pub fn logged(user_text: impl Into<String>, detail: impl Display) -> String {
    let text = user_text.into();
    tracing::warn!(%detail, "{text}");
    text
}
