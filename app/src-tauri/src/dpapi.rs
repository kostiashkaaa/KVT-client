//! Шифрование секретов (ссылки подписок, ключи серверов) через DPAPI Windows.
//! Ключ привязан к учётной записи пользователя: другой пользователь или копия
//! файла на другом компьютере расшифровать данные не смогут.

#![allow(unsafe_code)]

use std::io;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// Дополнительная «соль»: данные, зашифрованные другими программами того же
/// пользователя, не подойдут.
const ENTROPY: &[u8] = b"KVT subscriptions v1";

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr().cast_mut(),
    }
}

/// Копирует результат DPAPI и освобождает память, выделенную системой.
fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: при успехе DPAPI выделил cbData байт по pbData через LocalAlloc.
    let data = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: освобождаем ровно тот буфер, который выделил DPAPI, один раз.
    unsafe { LocalFree(out.pbData.cast()) };
    data
}

pub fn protect(plain: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob(plain);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: входные буферы живы на время вызова, интерфейс запрещён флагом.
    let ok = unsafe {
        CryptProtectData(
            &input,
            null(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(take(out))
}

pub fn unprotect(cipher: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob(cipher);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: как в protect; описание данных не запрашиваем.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(take(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let secret = b"vless://b831381d-6324-4d53-ad4f-8cda48b30811@host:443";
        let cipher = protect(secret).unwrap();
        assert!(!cipher.windows(8).any(|w| w == b"b831381d"));
        assert_eq!(unprotect(&cipher).unwrap(), secret);
    }

    #[test]
    fn tampered_data_is_rejected() {
        let mut cipher = protect(b"secret").unwrap();
        let last = cipher.len() - 1;
        cipher[last] ^= 0xFF;
        assert!(unprotect(&cipher).is_err());
    }
}
