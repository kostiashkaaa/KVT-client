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

/// Права на саму службу (не на её файлы) строкой SDDL — например, чтобы обычный
/// пользователь мог её запустить. `handle` — SC_HANDLE открытой службы.
pub fn set_service_sddl(handle: usize, sddl: &str) -> io::Result<()> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::System::Services::SetServiceObjectSecurity;
    let wide: Vec<u16> = std::ffi::OsStr::new(sddl)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut sd: *mut c_void = std::ptr::null_mut();
    // SAFETY: строка заканчивается нулём; sd освобождается LocalFree ниже.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: handle — открытая служба с правом WRITE_DAC, sd — разобранный дескриптор.
    let ok =
        unsafe { SetServiceObjectSecurity(handle as *mut c_void, DACL_SECURITY_INFORMATION, sd) };
    let result = if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    // SAFETY: sd выделен ConvertStringSecurityDescriptor… и освобождается один раз.
    unsafe { LocalFree(sd) };
    result
}

/// Счётчики адаптера по имени: (принято, отправлено) байт с его создания.
/// `None` — адаптера нет (ядро не запущено или режим Zapret).
pub fn adapter_octets(alias: &str) -> Option<(u64, u64)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, GetIfEntry2, MIB_IF_ROW2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    let wide: Vec<u16> = std::ffi::OsStr::new(alias)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: строка заканчивается нулём, luid — выходной параметр.
    if unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) } != 0 {
        return None;
    }
    // SAFETY: MIB_IF_ROW2 — простые данные, нули допустимы; GetIfEntry2 читает
    // InterfaceLuid и заполняет остальное.
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = luid;
    // SAFETY: row — структура точного типа на стеке.
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return None;
    }
    Some((row.InOctets, row.OutOctets))
}

/// Значение `DisabledComponents` (DWORD) из параметров IPv6; `None` — его нет.
/// Смысл значения — в [`kvt_core::compile::ipv6_enabled`].
pub fn ipv6_disabled_components() -> Option<u32> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
    let key = wide(r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters");
    let name = wide("DisabledComponents");
    let mut value: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as u32;
    // SAFETY: строки заканчиваются нулём; RRF_RT_REG_DWORD пишет ровно 4 байта в value.
    let code = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut len,
        )
    };
    (code == 0).then_some(value)
}

/// Устройства Wintun адаптера KVT. GUID ядра выводят из имени адаптера
/// (`compile::TUN_INTERFACE` = "KVT"), байты md5 читаются как GUID:
/// Xray — md5("KVT"), sing-box (sing-tun) — md5("wintun" + "KVT").
/// Пересчитать (PowerShell): `New-Object Guid (,[byte[]][Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("KVT")))`.
pub const KVT_WINTUN_DEVICES: [&str; 2] = [
    r"SWD\WINTUN\{E3B1C9E9-0F9E-2E8B-43A9-5F78C75937F9}",
    r"SWD\WINTUN\{C1FBC9FB-8C1C-8D44-652C-5CBE24FBF960}",
];

/// Убирает оставшееся от прежнего запуска устройство Wintun с этим ID экземпляра.
///
/// Служба завершает ядро принудительно, и Wintun не успевает удалить своё устройство.
/// Сам он убирает такие устройства в фоне при следующем открытии адаптера — но ядро
/// тут же создаёт адаптер с тем же GUID, упирается в ещё не убранное устройство и
/// через 15 с сдаётся («Cannot create a file when that file already exists»).
/// Поэтому служба убирает устройство сама до запуска ядра, так же, как Wintun
/// (`AdapterRemoveInstance`: DIF_REMOVE). Удаляется в любом состоянии: ядро KVT не
/// работает, значит устройство осталось от него. Если ждать, пока Windows уберёт
/// его сама, — не дожидаешься (на компьютере пользователя интерфейс жил дольше 3 с
/// после каждой остановки). GUID тот же, поэтому новое устройство получит прежний
/// интерфейс. Вызывать, только когда ядро KVT не работает. `Ok(true)` — удалено.
pub fn remove_stale_wintun(instance_id: &str) -> io::Result<bool> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiCallClassInstaller, SetupDiCreateDeviceInfoList, SetupDiDestroyDeviceInfoList,
        SetupDiOpenDeviceInfoW, SetupDiSetClassInstallParamsW, DIF_REMOVE, DI_REMOVEDEVICE_GLOBAL,
        GUID_DEVCLASS_NET, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_REMOVEDEVICE_PARAMS,
    };
    use windows_sys::Win32::Foundation::ERROR_NO_SUCH_DEVINST;

    struct DevInfo(isize);
    impl Drop for DevInfo {
        fn drop(&mut self) {
            // SAFETY: набор создан SetupDiCreateDeviceInfoList и освобождается один раз.
            unsafe { SetupDiDestroyDeviceInfoList(self.0) };
        }
    }

    // SAFETY: класс — константа, окно не нужно.
    let set = unsafe { SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, std::ptr::null_mut()) };
    if set == -1 {
        return Err(io::Error::last_os_error());
    }
    let set = DevInfo(set);
    let id: Vec<u16> = instance_id.encode_utf16().chain(Some(0)).collect();
    // SAFETY: SP_DEVINFO_DATA — простые данные; cbSize задаётся ниже, как требует API.
    let mut data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
    data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
    // SAFETY: строка заканчивается нулём, data — выходной параметр точного типа.
    // Флаги 0: открывается и неподключённое устройство.
    if unsafe { SetupDiOpenDeviceInfoW(set.0, id.as_ptr(), std::ptr::null_mut(), 0, &mut data) }
        == 0
    {
        let err = io::Error::last_os_error();
        #[allow(clippy::cast_possible_wrap)]
        if err.raw_os_error() == Some(ERROR_NO_SUCH_DEVINST as i32) {
            return Ok(false);
        }
        return Err(err);
    }
    let params = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_REMOVE,
        },
        Scope: DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };
    // SAFETY: params живёт до конца вызовов, размер — точный размер структуры.
    let ok = unsafe {
        SetupDiSetClassInstallParamsW(
            set.0,
            &data,
            &params.ClassInstallHeader,
            std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
        ) != 0
            && SetupDiCallClassInstaller(DIF_REMOVE, set.0, &data) != 0
    };
    if !ok {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
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

    /// GUID устройств выведены из имени адаптера — при переименовании их надо пересчитать.
    #[test]
    fn wintun_devices_match_adapter_name() {
        assert_eq!(kvt_core::compile::TUN_INTERFACE, "KVT");
        for id in KVT_WINTUN_DEVICES {
            assert!(
                id.starts_with(r"SWD\WINTUN\{") && id.ends_with('}') && id.len() == 49,
                "{id}"
            );
        }
    }

    /// Нет устройства — нечего убирать, и это не ошибка (права администратора не нужны).
    #[test]
    fn missing_wintun_device_is_not_an_error() {
        let id = r"SWD\WINTUN\{00000000-0000-0000-0000-000000000000}";
        assert!(!remove_stale_wintun(id).unwrap());
    }

    #[test]
    fn adapter_counters() {
        assert!(adapter_octets("Loopback Pseudo-Interface 1").is_some());
        assert!(adapter_octets("KVT-нет-такого-адаптера").is_none());
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
