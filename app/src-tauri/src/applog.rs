//! Журнал приложения на диске: `%LOCALAPPDATA%\dev.kvt.client\logs\kvt.log`
//! (+ `.1`), по 1 МБ. События и ошибки — без ключей, ссылок подписок и адресов
//! серверов (`kvt_core::redact`). Паника тоже попадает в журнал.

use kvt_core::diaglog::{self, LogFile};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

static LOG: OnceLock<Arc<LogFile>> = OnceLock::new();

/// Сколько журнала уходит в экспорт диагностики.
pub const EXPORT_BYTES: u64 = 512 * 1024;

pub fn init(dir: &Path) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tao=warn,wry=warn,reqwest=warn,hyper=warn"));
    let file = LogFile::open(dir.join("kvt.log")).ok();
    let file_layer = file.clone().map(|f| {
        fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || f.writer())
    });
    // В отладочной сборке — ещё и в консоль `npm run tauri dev`.
    let console_layer = cfg!(debug_assertions).then(|| fmt::layer().with_writer(std::io::stderr));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(console_layer)
        .try_init();
    if let Some(f) = file {
        diaglog::install_panic_hook(Arc::clone(&f));
        let _ = LOG.set(f);
    }
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "KVT запущен");
}

/// Конец журнала для экспорта диагностики.
pub fn tail() -> String {
    LOG.get().map(|l| l.tail(EXPORT_BYTES)).unwrap_or_default()
}
