//! Аудит ПК (выводы — `kvt_core::audit`). Сбор фактов только читает систему;
//! исправления выполняются по кнопке: свои — здесь, с правами пользователя,
//! остальные — службой (`Request::AuditFix`).

use crate::service_client;
use kvt_core::audit::{self, Finding, Fix, OwnDirs};
use kvt_core::ipc::{Request, Response};
use serde::Serialize;
use std::os::windows::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const INTERNET_SETTINGS: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub findings: Vec<Finding>,
    /// Сколько длился сбор сведений, мс.
    pub ms: u64,
}

/// Каталоги KVT: программа и `ProgramData\KVT` (обновлённый комплект zapret).
fn own() -> OwnDirs {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.display().to_string()))
        .unwrap_or_default();
    let data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("KVT");
    audit::own_dirs(&[exe_dir, data.display().to_string()])
}

fn facts() -> Result<audit::Facts, String> {
    let out = Command::new("powershell.exe")
        .args(audit::powershell_args())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| {
            kvt_core::trf!(
                "Не удалось запустить PowerShell: {e}",
                "Couldn't start PowerShell: {e}"
            )
        })?;
    audit::parse_facts(&String::from_utf8_lossy(&out.stdout))
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("{program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(kvt_core::trf!(
            "{program} завершился с кодом {}",
            "{program} exited with code {}",
            status.code().unwrap_or(-1)
        ))
    }
}

#[tauri::command]
pub async fn pc_audit() -> Result<AuditReport, String> {
    let start = Instant::now();
    let facts = tokio::task::spawn_blocking(facts).await.map_err(|_| {
        kvt_core::i18n::tr(
            "Сбор сведений прервался",
            "Collecting information was interrupted",
        )
    })??;
    Ok(AuditReport {
        findings: audit::analyze(&facts, &own()),
        ms: start.elapsed().as_millis() as u64,
    })
}

#[tauri::command]
pub async fn pc_audit_fix(fix: Fix) -> Result<(), String> {
    match fix {
        Fix::StopZapret => match service_client::call(Request::StopConflicts).await? {
            Response::Conflicts { conflicts } if conflicts.is_empty() => Ok(()),
            Response::Conflicts { .. } => Err(kvt_core::i18n::tr(
                "Не всё удалось остановить — проверьте ещё раз через несколько секунд",
                "Not everything could be stopped — check again in a few seconds",
            )
            .into()),
            Response::Error { message } => Err(message),
            _ => Err(crate::errors::unexpected().into()),
        },
        Fix::Service(request) => match service_client::call(Request::AuditFix(request)).await? {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(message),
            _ => Err(crate::errors::unexpected().into()),
        },
        other => tokio::task::spawn_blocking(move || fix_here(&other))
            .await
            .map_err(|_| {
                kvt_core::i18n::tr("Исправление прервалось", "The fix was interrupted").to_string()
            })?,
    }
}

/// Исправления с правами пользователя.
fn fix_here(fix: &Fix) -> Result<(), String> {
    match fix {
        Fix::DisableSystemProxy => {
            run(
                "reg.exe",
                &[
                    "add",
                    INTERNET_SETTINGS,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ],
            )?;
            // Сценария настройки может и не быть — тогда удалять нечего.
            let _ = run(
                "reg.exe",
                &["delete", INTERNET_SETTINGS, "/v", "AutoConfigURL", "/f"],
            );
            wininet::settings_changed();
            Ok(())
        }
        Fix::CloseProcess { pid, .. } => close_process(*pid),
        Fix::DisableUserAutostart { id } => {
            let facts = facts()?;
            let entry = audit::zapret_autostart_by_id(&facts, id, &own())
                .filter(|a| !a.location.machine_wide())
                .ok_or(kvt_core::i18n::tr(
                    "Запись автозагрузки не найдена — возможно, её уже убрали",
                    "The autostart entry wasn't found — it may have been removed already",
                ))?;
            let key = entry.location.approved_key().ok_or(kvt_core::i18n::tr(
                "Эту запись нельзя отключить",
                "This entry can't be disabled",
            ))?;
            run(
                "reg.exe",
                &[
                    "add",
                    key,
                    "/v",
                    &entry.name,
                    "/t",
                    "REG_BINARY",
                    "/d",
                    audit::STARTUP_DISABLED,
                    "/f",
                ],
            )
        }
        Fix::StopZapret | Fix::Service(_) => Err(kvt_core::i18n::tr(
            "Это исправление выполняет служба",
            "This fix is done by the service",
        )
        .into()),
    }
}

/// Имя образа процесса по PID (`tasklist /FO CSV`), `None` — процесса нет.
fn image_name(pid: u32) -> Option<String> {
    let out = Command::new("tasklist.exe")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.starts_with('"'))?;
    let name = line.split("\",\"").next()?.trim_matches('"');
    // Колонка PID должна совпасть: так «нет задач» на любом языке не примем за процесс.
    let pid_col = line.split("\",\"").nth(1)?.trim_matches('"');
    (pid_col == pid.to_string()).then(|| name.to_owned())
}

/// Закрывает другой VPN-клиент: сначала просьбой закрыться, потом принудительно.
/// Закрывается только процесс из списка VPN-клиентов — PID проверяется заново.
fn close_process(pid: u32) -> Result<(), String> {
    let name = image_name(pid).ok_or(kvt_core::i18n::tr(
        "Программа уже закрыта",
        "The app is already closed",
    ))?;
    if !audit::is_vpn_process_name(&name) {
        return Err(kvt_core::i18n::tr(
            "Этот процесс не похож на VPN-клиент — KVT его не закрывает",
            "This process doesn't look like a VPN client — KVT won't close it",
        )
        .into());
    }
    let pid_arg = pid.to_string();
    let _ = run("taskkill.exe", &["/PID", &pid_arg]);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if image_name(pid).is_none() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = run("taskkill.exe", &["/PID", &pid_arg, "/F"]);
    std::thread::sleep(Duration::from_millis(500));
    if image_name(pid).is_none() {
        Ok(())
    } else {
        Err(kvt_core::trf!(
            "Не удалось закрыть {name} — закройте программу вручную (она может быть запущена от администратора)",
            "Couldn't close {name} — close it manually (it may be running as administrator)"
        ))
    }
}

/// Уведомление WinINet о смене настроек прокси: браузеры подхватят её сразу.
mod wininet {
    #![allow(unsafe_code)]
    use windows_sys::Win32::Networking::WinInet::InternetSetOptionW;

    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;

    pub fn settings_changed() {
        // SAFETY: обе опции не принимают буфер (null, длина 0) и не трогают память.
        unsafe {
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null(),
                0,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Аудит этого компьютера: `cargo test -p kvt-app real_pc_audit -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "запускает PowerShell и читает систему"]
    async fn real_pc_audit() {
        let f = facts().unwrap();
        println!(
            "адаптеров {}, процессов {}, антивирусов {:?}, автозапуск {}, браузеров {}, teredo {:?}",
            f.adapters.len(),
            f.processes.len(),
            f.antivirus,
            f.autostart.len(),
            f.browsers.len(),
            f.teredo
        );
        assert!(!f.processes.is_empty() && !f.adapters.is_empty());
        let report = pc_audit().await.unwrap();
        println!("{} мс", report.ms);
        for f in &report.findings {
            println!(
                "{:?} {:?} {} — {} {:?}",
                f.group, f.level, f.title, f.detail, f.fix
            );
        }
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn own_process_is_not_listed() {
        assert!(image_name(std::process::id()).is_some());
        assert!(image_name(u32::MAX - 1).is_none());
    }
}
