//! Понятные тексты ошибок. Пользователь видит, что случилось и что делать, а
//! исходный технический текст (на английском, с кодами) уходит в журнал.

use std::fmt::Display;

/// Замок состояния отравлен — значит, раньше в программе была паника (она уже в журнале).
pub const STATE: &str = "Внутренняя ошибка KVT. Перезапустите программу; если повторится — сохраните диагностику в разделе «Проверка».";

/// Служба ответила не тем, что ждали: почти всегда это разные версии окна и службы.
pub const UNEXPECTED: &str =
    "Служба KVT ответила непонятно — похоже, окно и служба разных версий. Переустановите KVT.";

/// Служба отвергла приветствие: окно и служба разных версий.
pub const VERSION_MISMATCH: &str = "Окно KVT и служба разных версий — похоже, обновление прервалось. Установите KVT заново (полная установка со страницы загрузки): настройки и подписки сохранятся.";

/// Служба не запущена.
pub const NO_SERVICE: &str = "Служба KVT не запущена, поэтому подключиться нельзя. Перезагрузите компьютер или переустановите KVT — служба запустится вместе с Windows.";

/// Для `map_err` у замков состояния.
pub fn state<T>(_: T) -> String {
    STATE.into()
}

/// Ошибка файла: что не получилось и почему — по-русски.
pub fn io(what: &str, e: &std::io::Error) -> String {
    tracing::warn!(error = %e, "{what}");
    use std::io::ErrorKind as K;
    const ERROR_DISK_FULL: i32 = 112;
    let why = match e.kind() {
        K::PermissionDenied => {
            "нет доступа — возможно, файл открыт другой программой или его блокирует антивирус"
        }
        K::NotFound => "файл или папка не найдены",
        _ if e.raw_os_error() == Some(ERROR_DISK_FULL) => "на диске закончилось место",
        _ => "ошибка диска",
    };
    format!("{what}: {why}.")
}

/// Ошибка сети без адреса (в нём бывает токен подписки) и без английского.
pub fn net(e: &reqwest::Error) -> String {
    tracing::debug!(error = %e.to_string().split(" for url").next().unwrap_or_default(), "ошибка сети");
    if e.is_timeout() {
        "нет ответа".into()
    } else if e.is_connect() {
        "не удалось подключиться".into()
    } else if e.is_redirect() {
        "слишком много перенаправлений".into()
    } else if e.is_body() || e.is_decode() {
        "соединение оборвалось".into()
    } else if e.is_status() {
        e.status()
            .map(|s| format!("ошибка сервера {}", s.as_u16()))
            .unwrap_or_else(|| "ошибка сервера".into())
    } else {
        "ошибка сети".into()
    }
}

/// Записать в журнал и вернуть текст для пользователя.
pub fn logged(user_text: impl Into<String>, detail: impl Display) -> String {
    let text = user_text.into();
    tracing::warn!(%detail, "{text}");
    text
}
