//! Манифест установки: SHA-256 `kvt.exe`, которому служба разрешает управлять VPN.
//!
//! Пишется командой `kvt-service install` (её вызывает установщик) в
//! `C:\ProgramData\KVT\manifest.json` — каталог только для SYSTEM и администраторов.
//! Пока сертификата подписи нет, это вторая проверка клиента после пути: подменить
//! `kvt.exe` в Program Files может только администратор, но и тогда служба его не
//! примет, пока установщик (или обновление) не запишет новый хэш.
//!
//! При разработке (служба не из Program Files) манифеста нет — проверяется только путь.

use kvt_core::rulesync::sha256_hex;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

const FILE: &str = "manifest.json";
pub const CLIENT: &str = "kvt.exe";

fn path() -> PathBuf {
    crate::supervisor::data_dir().join(FILE)
}

/// Служба установлена в Program Files (а не запущена из каталога сборки).
pub fn installed(exe_dir: &Path) -> bool {
    let Some(pf) = std::env::var_os("ProgramFiles") else {
        return false;
    };
    let pf = PathBuf::from(pf).to_string_lossy().to_lowercase();
    exe_dir.to_string_lossy().to_lowercase().starts_with(&pf)
}

/// Записывает хэш `kvt.exe` из каталога службы; вне Program Files — убирает манифест.
pub fn write(exe_dir: &Path) -> anyhow::Result<()> {
    if !installed(exe_dir) {
        let _ = std::fs::remove_file(path());
        return Ok(());
    }
    let bytes = std::fs::read(exe_dir.join(CLIENT))?;
    crate::supervisor::secure_dir(&crate::supervisor::data_dir()).map_err(anyhow::Error::msg)?;
    let body = json!({ "client": CLIENT, "sha256": sha256_hex(&bytes) });
    std::fs::write(path(), serde_json::to_vec_pretty(&body)?)?;
    Ok(())
}

fn expected() -> Option<String> {
    let bytes = std::fs::read(path()).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("sha256")?.as_str().map(str::to_ascii_lowercase)
}

/// Проверка клиента по манифесту. Хэш файла запоминается по размеру и времени
/// изменения: 15 МБ не читаются на каждое подключение окна к службе.
#[derive(Default)]
pub struct Verifier {
    cache: Mutex<Option<(u64, SystemTime, String)>>,
}

impl Verifier {
    pub fn check(&self, image: &Path) -> bool {
        let Some(expected) = expected() else {
            return true;
        };
        let Ok(meta) = std::fs::metadata(image) else {
            return false;
        };
        let (len, modified) = (
            meta.len(),
            meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        );
        if let Ok(cache) = self.cache.lock() {
            if let Some((l, m, h)) = cache.as_ref() {
                if *l == len && *m == modified {
                    return *h == expected;
                }
            }
        }
        let Ok(bytes) = std::fs::read(image) else {
            return false;
        };
        let actual = sha256_hex(&bytes);
        if let Ok(mut cache) = self.cache.lock() {
            *cache = Some((len, modified, actual.clone()));
        }
        actual == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dirs_are_not_installed() {
        assert!(!installed(Path::new(
            r"C:\Users\x\Pet-Projects\KVT-client\target\debug"
        )));
        if let Some(pf) = std::env::var_os("ProgramFiles") {
            assert!(installed(&PathBuf::from(pf).join("KVT")));
        }
    }
}
