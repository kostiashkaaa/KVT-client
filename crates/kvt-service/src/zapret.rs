//! winws (zapret Flowseal) в службе.
//!
//! - Аргументы — только из стратегий комплекта, через белый список
//!   `kvt_core::zapret`; от приложения приходит лишь имя стратегии.
//! - Перед запуском сверяются SHA-256 winws.exe, WinDivert и cygwin1.dll.
//! - Списки лежат в `ProgramData\KVT\zapret` (только SYSTEM и администраторы):
//!   списки Flowseal плюс свои `*-user.txt` с доменами zapret и адресами
//!   VPN-серверов, которые winws не трогает.
//! - `service.bat` не вызывается: никаких чужих служб и процессов KVT не
//!   удаляет. TCP timestamps включаются, только если это разрешено в настройках.
//!
//! Комплектов два: поставленный с KVT (рядом со службой) и обновлённый кнопкой
//! «Обновить» (`ProgramData\KVT\zapret-bundle`). Обновление берёт из релиза
//! Flowseal стратегии и списки — это данные, они проходят белый список. Исполняемые
//! файлы принимаются, только если их хэш KVT уже знает; иначе остаются прежние.
//!
//! Состав: `bundle` — комплект и его проверка, `system` — драйвер и чужие обходы, `stage` —
//! распаковка, `update` — обновление и переустановка, `launch` — запуск winws; `error` — ошибки.

mod error;
pub use error::ZapretError;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_LIST: u64 = 5 * 1024 * 1024;

mod bundle;
mod launch;
mod stage;
mod system;
#[cfg(test)]
mod tests;
mod update;

pub use bundle::{info, strategies};
pub use launch::{server_addresses, start, ServerAddresses, Winws};
pub use system::{conflicts, remove_driver_if_unused, stop_conflicts};
pub use update::{blocking, fetch_update, install_update, interrupted, repair, Prepared};
