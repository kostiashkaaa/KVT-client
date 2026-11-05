//! «О программе» и запуск службы из окна.
//!
//! - версии KVT, ядер и Wintun (`cores\versions.json` рядом с kvt.exe кладёт
//!   `fetch-cores.ps1`), ссылки на исходники и страницу загрузки;
//! - тексты лицензий — в папке `licenses` рядом с kvt.exe;
//! - «Запустить службу»: установщик даёт интерактивным пользователям право
//!   `SERVICE_START`, поэтому прав администратора не нужно.
//!
//! Ссылки открываются только из фиксированного списка: окно не может попросить
//! открыть произвольный адрес или файл.

#![allow(unsafe_code)]

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Исходники и страница загрузки (новые версии — вручную, 5.7).
pub const SOURCE_URL: &str = "https://github.com/kostiashkaaa/KVT-client";
const SERVICE_NAME: &str = "KVTService";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct About {
    version: &'static str,
    /// Компонент → версия (xray, sing-box, wintun). Пусто — файла нет (сборка без ядер).
    cores: BTreeMap<String, String>,
    source_url: &'static str,
    /// Есть папка с текстами лицензий (в установленном KVT).
    licenses: bool,
}

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(PathBuf::from)
}

#[tauri::command]
pub fn about_info() -> About {
    let dir = exe_dir();
    let cores = dir
        .as_ref()
        .and_then(|d| std::fs::read(d.join("cores").join("versions.json")).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    About {
        version: env!("CARGO_PKG_VERSION"),
        cores,
        source_url: SOURCE_URL,
        licenses: dir.is_some_and(|d| d.join("licenses").is_dir()),
    }
}

/// Что окно может открыть: исходники, страница загрузки, папка лицензий.
#[tauri::command]
pub fn open_link(target: String) -> Result<(), String> {
    let what = match target.as_str() {
        "source" => SOURCE_URL.to_owned(),
        "releases" => format!("{SOURCE_URL}/releases"),
        "latest" => format!("{SOURCE_URL}/releases/latest"),
        "licenses" => exe_dir()
            .map(|d| d.join("licenses"))
            .filter(|d| d.is_dir())
            .ok_or("Папка с лицензиями есть только в установленном KVT.")?
            .to_string_lossy()
            .into_owned(),
        _ => return Err(crate::errors::STATE.into()),
    };
    shell_open(&what)
}

fn shell_open(what: &str) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    let file: Vec<u16> = what.encode_utf16().chain(Some(0)).collect();
    // SAFETY: строки заканчиваются нулём; окно-владелец не нужно.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Значения больше 32 — успех (так устроен ShellExecute).
    if result as usize > 32 {
        Ok(())
    } else {
        Err("Не удалось открыть — скопируйте адрес вручную.".into())
    }
}

/// Запускает службу KVT и ждёт, пока она начнёт отвечать (до 15 с).
#[tauri::command]
pub async fn start_service(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(start_blocking)
        .await
        .map_err(crate::errors::state)??;
    for _ in 0..30 {
        if let Ok(Some(_)) = crate::query_status().await {
            crate::tray::invalidate(&app);
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err("Служба запустилась, но не отвечает. Сохраните диагностику в разделе «Проверка».".into())
}

pub(crate) fn start_blocking() -> Result<(), String> {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_ACCESS_DENIED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DISABLED,
        ERROR_SERVICE_DOES_NOT_EXIST,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, StartServiceW, SC_MANAGER_CONNECT,
        SERVICE_START,
    };
    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    // SAFETY: все дескрипторы проверяются и закрываются ниже; строки с нулём.
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err("Не удалось обратиться к службам Windows.".into());
        }
        let service = OpenServiceW(manager, name.as_ptr(), SERVICE_START);
        let started = !service.is_null() && StartServiceW(service, 0, std::ptr::null()) != 0;
        let result = if started { Ok(()) } else { Err(GetLastError()) };
        if !service.is_null() {
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
        match result {
            Ok(()) | Err(ERROR_SERVICE_ALREADY_RUNNING) => Ok(()),
            Err(ERROR_SERVICE_DOES_NOT_EXIST) => Err(
                "Служба KVT не установлена. Переустановите KVT — установщик зарегистрирует её."
                    .into(),
            ),
            Err(ERROR_SERVICE_DISABLED) => Err(
                "Служба KVT отключена в «Службах» Windows. Включите для неё тип запуска «Автоматически» или переустановите KVT."
                    .into(),
            ),
            Err(ERROR_ACCESS_DENIED) => Err(
                "Нет прав запустить службу. Переустановите KVT — установщик выдаст их.".into(),
            ),
            Err(code) => Err(crate::errors::logged(
                "Служба KVT не запустилась. Сохраните диагностику в разделе «Проверка».",
                format!("StartService: {code}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_links_open() {
        assert!(open_link("file:///C:/Windows/System32/calc.exe".into()).is_err());
        assert!(open_link("cmd".into()).is_err());
    }
}
