//! Обёртки над Windows API. Единственный модуль с `unsafe`: каждая функция
//! маленькая, проверяет результат и сама освобождает ресурсы.

#![allow(unsafe_code)]

use std::ffi::{c_void, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Права на pipe службы: SYSTEM и администраторы — полный доступ, пользователи,
/// вошедшие в систему интерактивно, — чтение и запись. Остальным (сетевым,
/// анонимным, службам других учётных записей) доступа нет.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Дескриптор безопасности создаётся один раз и живёт до конца процесса.
struct Descriptor(*mut c_void);
// SAFETY: дескриптор только читается системой при создании pipe; он не меняется после создания.
unsafe impl Send for Descriptor {}
unsafe impl Sync for Descriptor {}

fn pipe_descriptor() -> io::Result<*mut c_void> {
    static SD: OnceLock<Result<Descriptor, i32>> = OnceLock::new();
    let sd = SD.get_or_init(|| {
        let sddl: Vec<u16> = std::ffi::OsStr::new(PIPE_SDDL)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: строка завершена нулём; при успехе система выделяет дескриптор
        // через LocalAlloc — мы намеренно не освобождаем его (нужен всё время работы).
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
        } else {
            Ok(Descriptor(sd))
        }
    });
    match sd {
        Ok(d) => Ok(d.0),
        Err(code) => Err(io::Error::from_raw_os_error(*code)),
    }
}

/// Создаёт экземпляр pipe с ограниченными правами и без удалённых клиентов.
pub fn create_pipe(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: pipe_descriptor()?,
        bInheritHandle: 0,
    };
    // SAFETY: attrs и дескриптор живы на время вызова, система их только читает.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
            )
    }
}

/// Полный путь к исполняемому файлу процесса на другом конце pipe.
pub fn pipe_client_image(pipe: &NamedPipeServer) -> io::Result<PathBuf> {
    let mut pid = 0u32;
    // SAFETY: handle принадлежит живому pipe, pid — валидный указатель.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    process_image(pid)
}

/// Полный путь к исполняемому файлу процесса.
pub fn process_image(pid: u32) -> io::Result<PathBuf> {
    // SAFETY: обычный вызов; результат проверяется и закрывается ниже.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: буфер на len символов; process открыт с нужными правами.
    let ok = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    };
    let err = io::Error::last_os_error();
    // SAFETY: закрываем ровно один раз открытый выше handle.
    unsafe { CloseHandle(process) };
    if ok == 0 {
        return Err(err);
    }
    Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
}

/// Запущен ли процесс с правами администратора (повышенный токен или SYSTEM).
pub fn is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: псевдо-handle текущего процесса закрывать не нужно; token проверяется ниже.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: буфер — структура TOKEN_ELEVATION точного размера.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: закрываем открытый выше token один раз.
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Job Object с флагом «убить все процессы при закрытии». Ядро помещается в него,
/// поэтому если служба упадёт или будет остановлена, ядро не останется сиротой.
pub struct Job(HANDLE);

// SAFETY: handle job-объекта можно использовать из любого потока.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    pub fn kill_on_close() -> io::Result<Self> {
        // SAFETY: без атрибутов и имени — анонимный job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Job(handle);
        // SAFETY: структура из простых полей, нули — допустимое значение.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: передаём указатель и точный размер структуры нужного класса.
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    pub fn assign(&self, process: RawHandle) -> io::Result<()> {
        // SAFETY: оба handle валидны на время вызова.
        if unsafe { AssignProcessToJobObject(self.0, process as HANDLE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: handle создан в kill_on_close и закрывается один раз.
        // Закрытие последнего handle завершает все процессы job-объекта.
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_valid() {
        assert!(!pipe_descriptor().unwrap().is_null());
    }

    #[tokio::test]
    async fn job_kills_child_on_drop() {
        let mut child = tokio::process::Command::new("cmd")
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        let job = Job::kill_on_close().unwrap();
        job.assign(child.raw_handle().unwrap()).unwrap();
        drop(job);
        // Код выхода при закрытии job не важен — важно, что процесс завершился сразу.
        tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .expect("процесс должен завершиться вместе с job")
            .unwrap();
    }

    #[tokio::test]
    async fn pipe_reports_client_image() {
        let name = format!(r"\\.\pipe\kvt-test-{}", std::process::id());
        let server = create_pipe(&name, true).unwrap();
        let _client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&name)
            .unwrap();
        server.connect().await.unwrap();
        let image = pipe_client_image(&server).unwrap();
        assert_eq!(image, std::env::current_exe().unwrap());
    }
}
