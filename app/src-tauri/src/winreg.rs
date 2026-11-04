//! Строковые значения в `HKEY_CURRENT_USER`: имя для уведомлений и автозапуск.
//! Только ветка текущего пользователя — прав администратора не нужно.

#![allow(unsafe_code)]

use std::io;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        #[allow(clippy::cast_possible_wrap)]
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// Создаёт ключ при необходимости и записывает строку.
pub fn set_string(key: &str, name: &str, value: &str) -> io::Result<()> {
    let (key, name, value) = (wide(key), wide(name), wide(value));
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: строки заканчиваются нулём, handle — выходной параметр.
    check(unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut handle,
            std::ptr::null_mut(),
        )
    })?;
    let bytes = u32::try_from(value.len() * 2).unwrap_or(u32::MAX);
    // SAFETY: handle открыт выше; данные — UTF-16 с нулём, длина в байтах.
    let result = check(unsafe {
        RegSetValueExW(
            handle,
            name.as_ptr(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            bytes,
        )
    });
    // SAFETY: закрываем открытый выше ключ один раз.
    unsafe { RegCloseKey(handle) };
    result
}

/// Читает строку; `None` — ключа или значения нет.
pub fn get_string(key: &str, name: &str) -> Option<String> {
    let (key, name) = (wide(key), wide(name));
    let mut buf = vec![0u16; 1024];
    let mut len = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
    // SAFETY: буфер на len байт, RRF_RT_REG_SZ гарантирует строку с нулём.
    let code = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if code != 0 {
        return None;
    }
    let chars = (len as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..chars]))
}

/// Удаляет значение; отсутствие — не ошибка.
pub fn delete_value(key: &str, name: &str) -> io::Result<()> {
    let (key, name) = (wide(key), wide(name));
    // SAFETY: строки заканчиваются нулём.
    let code = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_in_current_user() {
        let key = r"Software\KVT-test";
        set_string(key, "value", "Привет").unwrap();
        assert_eq!(get_string(key, "value").as_deref(), Some("Привет"));
        delete_value(key, "value").unwrap();
        assert_eq!(get_string(key, "value"), None);
        delete_value(key, "value").unwrap();
    }
}
