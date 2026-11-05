//! Автозапуск с Windows свёрнутым в трей: значение `KVT` в
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` с ключом `--tray` —
//! тогда окно не открывается, KVT сразу уходит в трей. Источник правды — реестр,
//! а не settings.json: его могут выключить и в «Диспетчере задач».

use tauri::command;

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const NAME: &str = "KVT";
/// Запуск без окна (автозапуск).
pub const TRAY_FLAG: &str = "--tray";

fn command_line() -> Result<String, String> {
    let exe =
        std::env::current_exe().map_err(|e| crate::errors::io("Не удалось найти kvt.exe", &e))?;
    Ok(format!("\"{}\" {TRAY_FLAG}", exe.display()))
}

/// Включён ли автозапуск именно этого kvt.exe.
#[command]
pub fn autostart_enabled() -> bool {
    match (crate::winreg::get_string(RUN, NAME), command_line()) {
        (Some(current), Ok(ours)) => current.eq_ignore_ascii_case(&ours),
        _ => false,
    }
}

#[command]
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let result = if enabled {
        crate::winreg::set_string(RUN, NAME, &command_line()?)
    } else {
        crate::winreg::delete_value(RUN, NAME)
    };
    result.map_err(|e| crate::errors::io("Не удалось изменить автозапуск", &e))
}

/// KVT установлен (kvt.exe в Program Files), а не запущен из каталога сборки.
pub fn installed() -> bool {
    let (Ok(exe), Some(pf)) = (std::env::current_exe(), std::env::var_os("ProgramFiles")) else {
        return false;
    };
    let pf = std::path::PathBuf::from(pf)
        .to_string_lossy()
        .to_lowercase();
    exe.to_string_lossy().to_lowercase().starts_with(&pf)
}

/// KVT запущен автозапуском — окно не открывать.
pub fn started_in_tray() -> bool {
    std::env::args().any(|a| a == TRAY_FLAG)
}
