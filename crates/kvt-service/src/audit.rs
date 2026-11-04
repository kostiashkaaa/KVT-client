//! Исправления из аудита ПК, которым нужны права администратора.
//!
//! Приложение присылает только [`ServiceFix`]. Имя службы и запись автозагрузки
//! служба не берёт на веру: заново собирает факты (`kvt_core::audit::SCRIPT`) и
//! действует, только если цель нашлась и действительно относится к чужому zapret.

use kvt_core::audit::{self, Location, OwnDirs, ServiceFix};
use std::os::windows::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Каталоги KVT: программа и `ProgramData\KVT`.
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

/// Запускает системную программу и ждёт её; ошибка — с кодом выхода.
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
        Err(format!(
            "{program} завершился с кодом {}",
            status.code().unwrap_or(-1)
        ))
    }
}

fn facts() -> Result<audit::Facts, String> {
    let out = Command::new("powershell.exe")
        .args(audit::powershell_args())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("не удалось запустить PowerShell: {e}"))?;
    audit::parse_facts(&String::from_utf8_lossy(&out.stdout))
}

pub fn fix(request: &ServiceFix) -> Result<(), String> {
    match request {
        ServiceFix::ResetWinHttpProxy => run("netsh.exe", &["winhttp", "reset", "proxy"]),
        ServiceFix::DisableTeredo => run(
            "netsh.exe",
            &["interface", "teredo", "set", "state", "disabled"],
        ),
        ServiceFix::DisableZapretService { name } => {
            let facts = facts()?;
            let own = own();
            let service = facts
                .services
                .iter()
                .find(|s| s.name == *name && audit::is_foreign_zapret_service(s, &own))
                .ok_or("Служба не найдена или не относится к zapret")?;
            // Сначала ручной запуск — тогда служба не поднимется снова после остановки.
            run("sc.exe", &["config", &service.name, "start=", "demand"])?;
            if service.state.eq_ignore_ascii_case("running") {
                // Остановка может занять время; ошибка здесь не отменяет смену запуска.
                let _ = run("sc.exe", &["stop", &service.name]);
            }
            Ok(())
        }
        ServiceFix::DisableAutostart { id } => {
            let facts = facts()?;
            let entry = audit::zapret_autostart_by_id(&facts, id, &own())
                .filter(|a| a.location.machine_wide())
                .ok_or("Запись автозагрузки не найдена — возможно, её уже убрали")?;
            match entry.location.approved_key() {
                Some(key) => run(
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
                ),
                None if entry.location == Location::Task => {
                    run("schtasks.exe", &["/Change", "/TN", &entry.name, "/Disable"])
                }
                None => Err("Эту запись нельзя отключить".into()),
            }
        }
    }
}
