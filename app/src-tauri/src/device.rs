//! ID устройства для провайдеров, которые ограничивают число устройств
//! (заголовок `x-hwid`, как у Happ и v2RayTun).
//!
//! В основе — случайный секрет установки в `device.key` (зашифрован DPAPI).
//! Провайдеру уходит не он, а производное от секрета и адреса сервера подписки:
//! у разных провайдеров разные ID — сопоставить их между собой нельзя; а при
//! повторном добавлении той же подписки ID прежний — место в лимите устройств не
//! тратится.

use crate::dpapi;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
use std::sync::Mutex;

const FILE: &str = "device.key";

/// Секрет читается с диска один раз за запуск.
static SECRET: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// ID устройства для сервера подписки `host`: 32 шестнадцатеричных знака.
pub fn hwid(dir: &Path, host: &str) -> io::Result<String> {
    let secret = secret(dir)?;
    let mut h = Sha256::new();
    h.update(b"kvt-hwid-v1\0");
    h.update(secret);
    h.update(host.to_ascii_lowercase().as_bytes());
    Ok(h.finalize()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn secret(dir: &Path) -> io::Result<[u8; 32]> {
    let mut cached = SECRET.lock().map_err(|_| {
        io::Error::other(kvt_core::i18n::tr(
            "состояние приложения повреждено",
            "app state is damaged",
        ))
    })?;
    if let Some(s) = *cached {
        return Ok(s);
    }
    let path = dir.join(FILE);
    let secret = match std::fs::read_to_string(&path) {
        Ok(text) => match open(&text) {
            Some(s) => s,
            // Файл с другого компьютера или другой учётной записи: для провайдера
            // это и есть другое устройство.
            None => create(&path)?,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => create(&path)?,
        // Файл есть, но не прочитался: новый секрет занял бы у провайдера ещё одно
        // место в лимите устройств — лучше ошибка.
        Err(e) => return Err(e),
    };
    *cached = Some(secret);
    Ok(secret)
}

fn open(text: &str) -> Option<[u8; 32]> {
    let sealed = STANDARD.decode(text.trim()).ok()?;
    dpapi::unprotect(&sealed).ok()?.try_into().ok()
}

fn create(path: &Path) -> io::Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| io::Error::other(e.to_string()))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("key.tmp");
    std::fs::write(&tmp, STANDARD.encode(dpapi::protect(&secret)?))?;
    std::fs::rename(tmp, path)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_per_provider_and_different_between_providers() {
        let dir = std::env::temp_dir().join(format!("kvt-device-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = hwid(&dir, "sub.example.com").unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, hwid(&dir, "SUB.example.com").unwrap());
        assert_ne!(a, hwid(&dir, "other.example.net").unwrap());
        // Секрет на диске зашифрован и сам в ID не виден.
        let raw = std::fs::read_to_string(dir.join(FILE)).unwrap();
        assert!(!raw.contains(&a));
        // После перезапуска (кэш сброшен) — тот же ID.
        *SECRET.lock().unwrap() = None;
        assert_eq!(a, hwid(&dir, "sub.example.com").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
