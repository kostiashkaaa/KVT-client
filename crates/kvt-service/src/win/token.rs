//! Токены процессов: от чьего имени запущен процесс и с какими правами.

use super::Process;
use std::io;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TokenElevationType, TokenElevationTypeLimited, TokenUser,
    TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Открытый токен процесса (только чтение); закрывается в Drop.
struct Token(HANDLE);

impl Token {
    fn current() -> io::Result<Self> {
        // SAFETY: псевдо-handle текущего процесса закрывать не нужно.
        Self::open(unsafe { GetCurrentProcess() })
    }

    fn of(process: &Process) -> io::Result<Self> {
        Self::open(process.0)
    }

    fn open(process: HANDLE) -> io::Result<Self> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: process — живой handle с правом запроса сведений; token проверяется ниже.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(token))
    }

    /// Сведение фиксированного размера (`TOKEN_ELEVATION`, `TOKEN_ELEVATION_TYPE`).
    fn query<T: Copy>(&self, class: i32, mut value: T) -> io::Result<T> {
        let mut len = 0u32;
        // SAFETY: буфер — значение типа T точного размера, который ждёт этот класс.
        let ok = unsafe {
            GetTokenInformation(
                self.0,
                class,
                (&mut value as *mut T).cast(),
                std::mem::size_of::<T>() as u32,
                &mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    /// Повышенный токен (запущен «от администратора» или SYSTEM).
    fn elevated(&self) -> bool {
        self.query(TokenElevation, TOKEN_ELEVATION { TokenIsElevated: 0 })
            .is_ok_and(|e| e.TokenIsElevated != 0)
    }

    /// Администратор с UAC, запустивший программу без повышения: права он может
    /// получить в любой момент, поэтому для службы он тоже администратор.
    fn limited_admin(&self) -> bool {
        self.query::<TOKEN_ELEVATION_TYPE>(TokenElevationType, 0)
            .is_ok_and(|t| t == TokenElevationTypeLimited)
    }

    /// SID учётной записи строкой («S-1-5-18» у SYSTEM).
    fn sid_string(&self) -> io::Result<String> {
        // TOKEN_USER и SID за ним; буфер выровнен по 8 байт.
        let mut buf = vec![0u64; 64];
        let mut len = 0u32;
        // SAFETY: буфер на 512 байт, его размер передаётся; SID пользователя меньше.
        let ok = unsafe {
            GetTokenInformation(
                self.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: функция заполнила в начале буфера TOKEN_USER, Sid указывает внутрь буфера.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: sid валиден, пока жив buf; строку выделяет система, освобождаем ниже.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: строка завершена нулём.
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        // SAFETY: len символов строки прочитаны выше.
        let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: строка выделена ConvertSidToStringSidW через LocalAlloc, освобождается один раз.
        unsafe { LocalFree(text.cast()) };
        Ok(result)
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: token открыт в open и закрывается один раз.
        unsafe { CloseHandle(self.0) };
    }
}

/// Запущен ли этот процесс с правами администратора (повышенный токен или SYSTEM).
pub fn is_elevated() -> bool {
    Token::current().is_ok_and(|t| t.elevated())
}

/// SID учётной записи этого процесса строкой («S-1-5-18» у службы).
pub(super) fn own_sid_string() -> io::Result<String> {
    Token::current()?.sid_string()
}

/// Пользователь Windows, от имени которого работает процесс.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub sid: String,
    /// Администратор: повышенный токен, SYSTEM или администратор с UAC без повышения.
    pub admin: bool,
}

pub(super) fn process_user(process: &Process) -> io::Result<User> {
    let token = Token::of(process)?;
    Ok(User {
        sid: token.sid_string()?,
        admin: token.elevated() || token.limited_admin(),
    })
}
