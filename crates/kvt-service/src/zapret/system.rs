//! zapret в системе: драйвер WinDivert и чужие обходы блокировок (службы и процессы).

use crate::dirs::Paths;

use super::ZapretError;
use super::CREATE_NO_WINDOW;
use kvt_core::ipc::{Conflict, DriverState};
use std::os::windows::process::CommandExt as _;
use std::path::Path;
use std::time::Duration;

const DRIVER_SERVICE: &str = "WinDivert";
/// Службы других обходов блокировок: с ними два winws портят друг другу пакеты.
const CONFLICTING_SERVICES: &[&str] = &[
    "zapret",
    "GoodbyeDPI",
    "discordfix_zapret",
    "winws1",
    "winws2",
];
const CONFLICTING_PROCESSES: &[&str] = &["winws.exe", "goodbyedpi.exe"];

pub(super) fn driver_state() -> DriverState {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let status = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service(DRIVER_SERVICE, ServiceAccess::QUERY_STATUS))
        .and_then(|s| s.query_status());
    match status {
        Err(_) => DriverState::Missing,
        Ok(s) if s.current_state == ServiceState::Running => DriverState::Running,
        Ok(_) => DriverState::Stopped,
    }
}

/// Драйвер WinDivert ставит сам winws при первом запуске; удалённый — поставится заново.
pub(super) fn remove_driver() -> Result<(), ZapretError> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(ZapretError::io)?;
    let Ok(service) = manager.open_service(
        DRIVER_SERVICE,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) else {
        return Ok(());
    };
    let _ = service.stop();
    service.delete().map_err(ZapretError::io)
}

/// При удалении KVT: драйвер убирается, если им сейчас не пользуется чужой winws.
pub fn remove_driver_if_unused(paths: &Paths) -> Result<(), ZapretError> {
    if conflicts(paths, None).iter().any(|(c, _)| !c.service) {
        return Err(ZapretError::DriverInUse);
    }
    remove_driver()
}

fn service_running(name: &str) -> bool {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return false;
    };
    manager
        .open_service(name, ServiceAccess::QUERY_STATUS)
        .and_then(|s| s.query_status())
        .is_ok_and(|st| st.current_state != ServiceState::Stopped)
}

/// PID процессов по имени образа (`tasklist`, независимо от языка Windows).
/// Абсолютный путь: запуск по имени нашёл бы файл рядом со службой.
fn pids(image: &str) -> Vec<u32> {
    let out = std::process::Command::new(crate::win::system_exe("tasklist.exe"))
        .args(["/FI", &format!("IMAGENAME eq {image}"), "/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split("\",\"").map(|f| f.trim_matches('"'));
            let name = fields.next()?;
            let pid = fields.next()?.parse().ok()?;
            name.eq_ignore_ascii_case(image).then_some(pid)
        })
        .collect()
}

/// Чужие обходы: службы и процессы winws/GoodbyeDPI не из комплектов KVT.
pub fn conflicts(paths: &Paths, own_pid: Option<u32>) -> Vec<(Conflict, Option<u32>)> {
    let mut out: Vec<(Conflict, Option<u32>)> = CONFLICTING_SERVICES
        .iter()
        .filter(|name| service_running(name))
        .map(|name| {
            (
                Conflict {
                    service: true,
                    name: (*name).to_owned(),
                },
                None,
            )
        })
        .collect();
    for image in CONFLICTING_PROCESSES {
        for pid in pids(image) {
            if Some(pid) == own_pid {
                continue;
            }
            let path = crate::win::process_image(pid).ok();
            if path.as_deref().is_some_and(|p| is_ours(paths, p)) {
                continue;
            }
            out.push((
                Conflict {
                    service: false,
                    name: path
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| (*image).to_owned()),
                },
                Some(pid),
            ));
        }
    }
    out
}

/// winws из комплекта KVT (основного или обновлённого).
fn is_ours(paths: &Paths, image: &Path) -> bool {
    [
        paths.zapret.join("bin").join("winws.exe"),
        paths.zapret_update.join("bin").join("winws.exe"),
    ]
    .iter()
    .any(|o| same_file(image, o))
}

/// Процесс, который можно завершить как конфликт: имя из `CONFLICTING_PROCESSES`,
/// и это не winws KVT.
fn is_foreign_bypass(paths: &Paths, image: &Path) -> bool {
    let name = image
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    CONFLICTING_PROCESSES
        .iter()
        .any(|c| c.eq_ignore_ascii_case(&name))
        && !is_ours(paths, image)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
    }
}

/// Останавливает найденное (службы — остановкой, процессы — завершением). Ничего не удаляет.
pub fn stop_conflicts(paths: &Paths, own_pid: Option<u32>) -> Vec<Conflict> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok();
    for (conflict, pid) in conflicts(paths, own_pid) {
        match pid {
            None => {
                if let Some(service) = manager
                    .as_ref()
                    .and_then(|m| m.open_service(&conflict.name, ServiceAccess::STOP).ok())
                {
                    let _ = service.stop();
                }
            }
            // Номер из tasklist мог перейти к другой программе: процесс открывается,
            // проверяется по образу и завершается через тот же handle.
            Some(pid) if Some(pid) != own_pid => {
                match crate::win::terminate_if(pid, |image| is_foreign_bypass(paths, image)) {
                    Ok(true) => tracing::info!(pid, "чужой обход блокировок остановлен"),
                    Ok(false) => tracing::info!(pid, "процесс сменился — не трогаем"),
                    Err(e) => tracing::warn!(pid, error = %e, "чужой обход не остановлен"),
                }
            }
            Some(_) => {}
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    conflicts(paths, own_pid)
        .into_iter()
        .map(|(c, _)| c)
        .collect()
}
