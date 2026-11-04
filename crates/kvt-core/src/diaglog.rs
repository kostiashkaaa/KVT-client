//! Журнал событий и ошибок на диске: приложение и служба пишут каждое в свой
//! каталог данных. Без него не разобраться, что случилось у пользователя, —
//! особенно со службой Windows, у которой нет консоли.
//!
//! - Ротация: текущий файл и один предыдущий (`.1`), каждый до [`MAX_BYTES`].
//! - Каждая строка проходит через [`crate::redact::text`]: ключи, ссылки подписок,
//!   UUID и адреса серверов на диск не попадают.
//! - Паника тоже записывается ([`install_panic_hook`]): в релизе `panic = "abort"`,
//!   и без этого причина падения терялась бы.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Размер одного файла журнала.
pub const MAX_BYTES: u64 = 1024 * 1024;

struct Inner {
    file: Option<File>,
    size: u64,
}

/// Файл журнала с ротацией. Пишется целыми строками под замком, поэтому строки
/// разных потоков не перемешиваются.
pub struct LogFile {
    path: PathBuf,
    max: u64,
    inner: Mutex<Inner>,
}

impl LogFile {
    /// Открывает (или создаёт) журнал. Каталог создаётся, если его нет.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Arc<Self>> {
        Self::with_limit(path, MAX_BYTES)
    }

    fn with_limit(path: impl Into<PathBuf>, max: u64) -> io::Result<Arc<Self>> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Arc::new(Self {
            path,
            max,
            inner: Mutex::new(Inner {
                file: Some(file),
                size,
            }),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn previous(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".1");
        PathBuf::from(name)
    }

    /// Дописывает текст (одну или несколько строк) после маскировки.
    pub fn append(&self, text: &str) {
        let mut text = crate::redact::text(text.trim_end_matches(['\r', '\n']));
        text.push_str("\r\n");
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.size + text.len() as u64 > self.max && inner.size > 0 {
            inner.file = None;
            let previous = self.previous();
            let _ = std::fs::remove_file(&previous);
            let _ = std::fs::rename(&self.path, &previous);
            inner.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
            inner.size = 0;
        }
        if let Some(file) = inner.file.as_mut() {
            if file.write_all(text.as_bytes()).is_ok() {
                inner.size += text.len() as u64;
            }
        }
    }

    /// Последние `max_bytes` журнала (предыдущий файл + текущий) — для экспорта.
    pub fn tail(&self, max_bytes: u64) -> String {
        // Под замком: ротация не должна случиться посреди чтения.
        let _guard = self.inner.lock();
        let mut out = Vec::new();
        for path in [self.previous(), self.path.clone()] {
            if let Ok(mut f) = File::open(&path) {
                let _ = f.read_to_end(&mut out);
            }
        }
        let start = out.len().saturating_sub(max_bytes as usize);
        let text = String::from_utf8_lossy(&out[start..]).into_owned();
        // Не начинаем с обрывка строки.
        match (start > 0, text.find('\n')) {
            (true, Some(i)) => text[i + 1..].to_owned(),
            _ => text,
        }
    }

    /// Писатель для `tracing_subscriber::fmt().with_writer(...)`: копит одно
    /// событие и записывает его целиком при сбросе.
    pub fn writer(self: &Arc<Self>) -> LineWriter {
        LineWriter {
            log: Arc::clone(self),
            buf: Vec::new(),
        }
    }
}

pub struct LineWriter {
    log: Arc<LogFile>,
    buf: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.log.append(&String::from_utf8_lossy(&self.buf));
            self.buf.clear();
        }
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Записывает панику в журнал (с местом в коде), затем вызывает прежний обработчик.
pub fn install_panic_hook(log: Arc<LogFile>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let place = info
            .location()
            .map(|l| format!(" ({}:{})", l.file(), l.line()))
            .unwrap_or_default();
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "без описания".into());
        log.append(&format!(
            "{} ПАНИКА{place}: {message}",
            timestamp(crate::netlog::now_ms())
        ));
        previous(info);
    }));
}

/// Время для строк журнала в UTC: `2026-11-04 12:30:05Z`.
pub fn timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let (y, mo, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

/// Дата по числу дней от 1970-01-01 (алгоритм Хиннанта).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Размер файла (0, если его нет).
pub fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kvt-diaglog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("kvt.log")
    }

    #[test]
    fn rotates_into_one_previous_file() {
        let path = tmp("rotate");
        let log = LogFile::with_limit(&path, 100).unwrap();
        for i in 0..20 {
            log.append(&format!("строка {i:02} ........"));
        }
        assert!(file_len(&path) <= 100);
        assert!(file_len(&log.previous()) <= 100);
        let tail = log.tail(10_000);
        assert!(tail.contains("строка 19"));
        assert!(!tail.contains("строка 00"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn secrets_never_reach_the_disk() {
        let path = tmp("redact");
        let log = LogFile::open(&path).unwrap();
        let mut w = log.writer();
        write!(
            w,
            "подписка https://sub.example.com/SECRET-TOKEN, ключ b831381d-6324-4d53-ad4f-8cda48b30811"
        )
        .unwrap();
        drop(w);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("sub.example.com"));
        assert!(!raw.contains("SECRET"));
        assert!(!raw.contains("b831381d"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn tail_starts_at_a_line_boundary() {
        let path = tmp("tail");
        let log = LogFile::open(&path).unwrap();
        log.append("первая длинная строка");
        log.append("вторая");
        assert_eq!(log.tail(16).trim(), "вторая");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn timestamps() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00Z");
        assert_eq!(timestamp(1_793_795_405_000), "2026-11-04 12:30:05Z");
    }
}
