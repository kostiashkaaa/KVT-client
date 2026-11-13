//! Манифест установки: SHA-256 `kvt.exe`, которому служба разрешает управлять VPN.
//!
//! Пишется командой `kvt-service install` (её вызывает установщик) в
//! `C:\ProgramData\KVT\manifest.json` — каталог только для SYSTEM и администраторов.
//! Пока сертификата подписи нет, это вторая проверка клиента после пути: подменить
//! `kvt.exe` в Program Files может только администратор, но и тогда служба его не
//! примет, пока установщик (или обновление) не запишет новый хэш.
//!
//! При разработке (служба не из Program Files) манифеста нет — проверяется только путь.
//! У установленной службы пропавший или битый манифест — отказ (fail-closed): помогает
//! переустановка, которая запишет его заново.

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

/// Ожидаемый хэш из файла манифеста; `None` — файла нет или он битый.
fn read_expected(manifest: &Path) -> Option<String> {
    parse_expected(&std::fs::read(manifest).ok()?)
}

/// Хэш из содержимого манифеста: ровно 64 шестнадцатеричных символа.
fn parse_expected(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let hash = value.get("sha256")?.as_str()?.to_ascii_lowercase();
    (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hash)
}

/// Проверка клиента по манифесту. Хэш файла запоминается по размеру и времени
/// изменения: 15 МБ не читаются на каждое подключение окна к службе.
pub struct Verifier {
    manifest: PathBuf,
    cache: Mutex<Option<(u64, SystemTime, String)>>,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new(path())
    }
}

impl Verifier {
    fn new(manifest: PathBuf) -> Self {
        Self {
            manifest,
            cache: Mutex::new(None),
        }
    }

    /// Манифест на месте и читается. Без него служба не примет ни одно окно.
    pub fn usable(&self) -> bool {
        read_expected(&self.manifest).is_some()
    }

    pub fn check(&self, image: &Path) -> bool {
        // Нет манифеста — отказ; об этом служба пишет в журнал при запуске.
        let Some(expected) = read_expected(&self.manifest) else {
            return false;
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

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kvt-manifest-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("каталог");
        dir
    }

    #[test]
    fn bad_manifests_are_rejected() {
        let good = "a".repeat(64);
        assert_eq!(
            parse_expected(format!(r#"{{"sha256":"{}"}}"#, good.to_uppercase()).as_bytes()),
            Some(good)
        );
        for bad in [
            &b""[..],
            b"\xff\xfe",
            b"[]",
            b"{}",
            br#"{"sha256":null}"#,
            br#"{"sha256":42}"#,
            br#"{"sha256":""}"#,
            br#"{"sha256":"abc"}"#,
            br#"{"sha256":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}"#,
        ] {
            assert_eq!(parse_expected(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn missing_or_broken_manifest_fails_closed() {
        let dir = temp("closed");
        let client = dir.join(CLIENT);
        std::fs::write(&client, b"client").expect("клиент");
        let verifier = Verifier::new(dir.join(FILE));
        assert!(!verifier.usable());
        assert!(
            !verifier.check(&client),
            "без манифеста окно не принимается"
        );
        std::fs::write(dir.join(FILE), b"{not json").expect("манифест");
        assert!(!verifier.check(&client), "битый манифест — тоже отказ");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn matching_client_is_accepted_and_changed_one_is_not() {
        let dir = temp("match");
        let client = dir.join(CLIENT);
        std::fs::write(&client, b"client v1").expect("клиент");
        let body = json!({ "client": CLIENT, "sha256": sha256_hex(b"client v1") });
        std::fs::write(dir.join(FILE), body.to_string()).expect("манифест");
        let verifier = Verifier::new(dir.join(FILE));
        assert!(verifier.usable());
        assert!(verifier.check(&client));
        std::fs::write(&client, b"client v2, other size").expect("подмена");
        assert!(!verifier.check(&client));
        let _ = std::fs::remove_dir_all(&dir);
    }

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
