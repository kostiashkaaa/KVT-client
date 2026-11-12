//! Клиент службы KVT: одно соединение на запрос, сначала проверка версии протокола.
//!
//! Pipe открывается с правами «чтение и запись данных» — без `FILE_APPEND_DATA`
//! (оно же `FILE_CREATE_PIPE_INSTANCE`): служба даёт пользователям только их, чтобы
//! никто не мог создать свой экземпляр `\\.\pipe\kvt-service` и принять команды
//! окна вместо службы. Пока служба остановлена, имя может занять любая программа —
//! поэтому окно ещё и проверяет владельца канала: это SYSTEM или администраторы, а
//! не обычный пользователь. Иначе ключ сервера из `Connect` ушёл бы чужой программе.

#![allow(unsafe_code)]

use kvt_core::ipc::{self, Request, Response, PIPE_NAME, PROTOCOL_VERSION};
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_PIPE_BUSY: i32 = 231;
/// `FILE_GENERIC_READ | FILE_WRITE_DATA`: не `GENERIC_WRITE` — в нём право создать
/// экземпляр pipe, которого у пользователей нет (см. `PIPE_SDDL` службы).
const ACCESS: u32 = 0x0012_0089 | 0x0000_0002;
/// Служба не может действовать от имени окна (`SECURITY_IDENTIFICATION`).
const SECURITY_IDENTIFICATION: u32 = 1 << 16;

/// Владелец канала — SYSTEM или администраторы: так создаёт pipe служба (или
/// `kvt-service --console` из терминала администратора). Обычный пользователь
/// сделать себя таким владельцем не может.
fn owned_by_system(pipe: &File) -> bool {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
    };
    let mut owner = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    // SAFETY: handle принадлежит открытому File; выходные указатели живы на время
    // вызова, дескриптор освобождается LocalFree ниже.
    let rc = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        tracing::warn!(code = rc, "не удалось узнать владельца канала службы");
        return false;
    }
    // SAFETY: owner указывает внутрь sd, который ещё не освобождён.
    let trusted = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
    };
    // SAFETY: sd выделен GetSecurityInfo и освобождается один раз.
    unsafe { LocalFree(sd) };
    trusted
}

fn open() -> Result<File, String> {
    for _ in 0..20 {
        let opened = std::fs::OpenOptions::new()
            .access_mode(ACCESS)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(PIPE_NAME);
        match opened {
            Ok(pipe) if owned_by_system(&pipe) => return Ok(pipe),
            Ok(_) => {
                tracing::error!("канал службы KVT создан не службой — команды не отправлены");
                return Err(kvt_core::i18n::tr(
                    "Канал связи со службой KVT занят другой программой. Перезагрузите компьютер; если повторится — проверьте его антивирусом.",
                    "The KVT service channel is taken by another program. Restart the computer; if it happens again, scan it with an antivirus.",
                )
                .into());
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err(crate::errors::no_service().into())
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                return Err(crate::errors::logged(
                    kvt_core::i18n::tr(
                        "Служба KVT не пустила это окно: она принимает команды только от KVT из папки установки. Запустите KVT из меню «Пуск» или переустановите его.",
                        "The KVT service refused this window: it only accepts commands from KVT in its install folder. Start KVT from the Start menu or reinstall it.",
                    ),
                    e,
                ))
            }
            Err(e) => {
                return Err(crate::errors::logged(
                    kvt_core::i18n::tr(
                        "Не удалось связаться со службой KVT. Повторите через несколько секунд.",
                        "Couldn't reach the KVT service. Try again in a few seconds.",
                    ),
                    e,
                ))
            }
        }
    }
    Err(kvt_core::i18n::tr(
        "Служба KVT занята — повторите через несколько секунд.",
        "The KVT service is busy — try again in a few seconds.",
    )
    .into())
}

fn broken() -> &'static str {
    kvt_core::i18n::tr(
        "Связь со службой KVT прервалась. Повторите; если не выйдет — перезагрузите компьютер.",
        "Lost connection to the KVT service. Try again; if it fails, restart the computer.",
    )
}

fn exchange(pipe: &mut File, request: &Request) -> Result<Response, String> {
    let frame = ipc::encode(request).map_err(|e| crate::errors::logged(broken(), e))?;
    pipe.write_all(&frame)
        .map_err(|e| crate::errors::logged(broken(), e))?;
    let mut header = [0u8; 4];
    pipe.read_exact(&mut header)
        .map_err(|e| crate::errors::logged(broken(), e))?;
    let len = ipc::frame_len(header).map_err(|e| crate::errors::logged(broken(), e))?;
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body)
        .map_err(|e| crate::errors::logged(broken(), e))?;
    ipc::decode(&body).map_err(|e| crate::errors::logged(crate::errors::unexpected(), e))
}

/// Служба отвергла приветствие: окно и служба разных версий (прерванное обновление).
/// Тогда «Запустить службу» не поможет — окно и трей просят переустановить KVT.
static MISMATCH: AtomicBool = AtomicBool::new(false);

pub fn version_mismatch() -> bool {
    MISMATCH.load(Ordering::Relaxed)
}

/// Окно спрашивает после статуса: служба отвечает, но другой версии.
#[tauri::command]
pub fn service_mismatch() -> bool {
    version_mismatch()
}

/// Сколько ждать ответа службы. Статус, журналы и сведения служба отдаёт, не
/// дожидаясь подключения, — если их нет дольше, служба зависла, и окно с треем не
/// должны висеть вместе с ней. Запуск, остановка и обслуживание идут сколько нужно:
/// у них свой предел внутри службы и отмена по «Отключить».
fn deadline(request: &Request) -> Option<Duration> {
    match request {
        Request::Hello { .. }
        | Request::Status
        | Request::NetLog
        | Request::ServiceLog
        | Request::ZapretStrategies
        | Request::ZapretInfo => Some(Duration::from_secs(15)),
        // tasklist, проверка страницы входа (до 10 с), пинг десятков серверов.
        Request::ZapretConflicts | Request::CaptiveCheck | Request::Ping { .. } => {
            Some(Duration::from_secs(60))
        }
        Request::Connect(_)
        | Request::StartZapret(_)
        | Request::Disconnect
        | Request::StopConflicts
        | Request::ZapretUpdate
        | Request::ZapretRepair
        | Request::AuditFix(_) => None,
    }
}

fn no_answer() -> &'static str {
    kvt_core::i18n::tr(
        "Служба KVT не ответила вовремя. Повторите через несколько секунд; если не выйдет — перезагрузите компьютер и сохраните диагностику.",
        "The KVT service didn't answer in time. Try again in a few seconds; if it fails, restart the computer and save diagnostics.",
    )
}

/// Запрос целиком — в отдельном потоке: pipe открыт синхронно (у асинхронного
/// клиента tokio права доступа не задать), а ответ на `Connect` идёт десятки секунд.
/// По истечении `deadline` окно перестаёт ждать; поток дочитает ответ сам и закроется.
pub async fn call(request: Request) -> Result<Response, String> {
    let deadline = deadline(&request);
    let task = tokio::task::spawn_blocking(move || call_blocking(request));
    let joined = match deadline {
        Some(limit) => match tokio::time::timeout(limit, task).await {
            Ok(joined) => joined,
            Err(_) => {
                tracing::warn!(secs = limit.as_secs(), "служба не ответила вовремя");
                return Err(no_answer().into());
            }
        },
        None => task.await,
    };
    joined.unwrap_or_else(|_| Err(broken().into()))
}

fn call_blocking(request: Request) -> Result<Response, String> {
    let mut pipe = open()?;
    let hello = exchange(
        &mut pipe,
        &Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            lang: kvt_core::i18n::current(),
        },
    );
    match hello {
        Ok(Response::Hello { .. }) => MISMATCH.store(false, Ordering::Relaxed),
        // Связь оборвалась — это не версия, а сбой канала.
        Err(e) if e != crate::errors::unexpected() => return Err(e),
        // Служба старше или новее: приветствие не принято или ответ не разобрался.
        _ => {
            MISMATCH.store(true, Ordering::Relaxed);
            return Err(crate::errors::version_mismatch().into());
        }
    }
    exchange(&mut pipe, &request)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pipe, созданный обычной программой пользователя (так выглядит перехват имени,
    /// пока служба остановлена), окно не принимает за службу.
    #[tokio::test]
    async fn pipe_of_a_user_program_is_not_trusted() {
        let name = format!(r"\\.\pipe\kvt-test-owner-{}", std::process::id());
        let _server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let client = std::fs::OpenOptions::new()
            .access_mode(ACCESS)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&name)
            .unwrap();
        // Под администратором владелец — группа администраторов: проверять нечего.
        let elevated = std::process::Command::new("net")
            .arg("session")
            .output()
            .is_ok_and(|o| o.status.success());
        if !elevated {
            assert!(!owned_by_system(&client));
        }
    }
}
