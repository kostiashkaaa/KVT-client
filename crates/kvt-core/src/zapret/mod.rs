//! zapret из [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).
//!
//! Стратегии Flowseal — это `.bat`-файлы. Мы их не запускаем: они вызывают
//! `service.bat`, меняют настройки TCP и убивают чужие процессы. Вместо этого
//! из файла извлекаются аргументы `winws.exe`, каждый флаг сверяется с белым
//! списком, а пути подставляет служба — только свои каталоги. winws работает от
//! SYSTEM, поэтому лишний флаг (например, `--debug=@файл`) — это запись в любой файл.
//!
//! Состав: `release` — релизы и хэши; `strategy` — стратегия и порядок; `bat` — разбор
//! `.bat`; `render` — аргументы для запуска; `lists` — пользовательские списки.

mod bat;
mod lists;
mod release;
mod render;
mod strategy;
#[cfg(test)]
mod tests;

pub use bat::parse_bat;
pub use lists::{user_lists, valid_domain, UserLists, EMPTY_HOSTLIST, EMPTY_IPSET};
pub use release::{
    archive_url, binary_known, newer, parse_release, valid_version, Release, ReleaseError,
    ARCHIVE_SHA256, BINARIES, BINARY_HASHES, FLOWSEAL_VERSION, RELEASES_API,
};
pub use render::{render, GameFilter, RenderContext};
pub use strategy::{sort, title, valid_id, Strategy, ZapretError, PREFERRED_ORDER};
