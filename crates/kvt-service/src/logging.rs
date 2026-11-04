//! Журнал службы на диске: `C:\ProgramData\KVT\logs\service.log` (+ `.1`), доступ
//! только у SYSTEM и администраторов. У службы Windows нет консоли, поэтому без
//! файла её ошибки терялись бы. Приложение получает журнал по IPC (`ServiceLog`)
//! уже без секретов — для экспорта диагностики.

use kvt_core::diaglog::{self, LogFile};
use std::sync::{Arc, OnceLock};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

static LOG: OnceLock<Arc<LogFile>> = OnceLock::new();

/// Сколько журнала отдаётся в экспорт диагностики.
pub const EXPORT_BYTES: u64 = 512 * 1024;

fn filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Только консоль: команды `install`, `uninstall`, `update-rules`.
pub fn init_console() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(std::io::stderr)
        .try_init();
}

/// Файл журнала и, при запуске `--console`, ещё и вывод в терминал.
pub fn init_service(console: bool) {
    let dir = crate::supervisor::data_dir().join("logs");
    let file = match crate::supervisor::secure_dir(&dir)
        .and_then(|()| LogFile::open(dir.join("service.log")).map_err(|e| e.to_string()))
    {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!("журнал службы не открылся: {e}");
            None
        }
    };
    let file_layer = file.clone().map(|f| {
        fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || f.writer())
    });
    let console_layer = console.then(|| fmt::layer().with_writer(std::io::stderr));
    let _ = tracing_subscriber::registry()
        .with(filter())
        .with(file_layer)
        .with(console_layer)
        .try_init();
    if let Some(f) = file {
        diaglog::install_panic_hook(Arc::clone(&f));
        let _ = LOG.set(f);
    }
}

/// Конец журнала для экспорта (пусто, если журнал не открылся).
pub fn tail() -> String {
    LOG.get().map(|l| l.tail(EXPORT_BYTES)).unwrap_or_default()
}
