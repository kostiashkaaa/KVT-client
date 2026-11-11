//! Автозапуск с Windows свёрнутым в трей: значение `KVT` в
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` с ключом `--tray` —
//! тогда окно не открывается, KVT сразу уходит в трей. Источник правды — реестр,
//! а не settings.json.
//!
//! Выключить автозапуск можно и мимо KVT: «Диспетчер задач» → «Автозагрузка» или
//! «Параметры» → «Приложения» → «Автозагрузка». Значение в `Run` при этом остаётся,
//! а Windows ставит отметку в `Explorer\StartupApproved\Run` и программу не запускает.
//! Поэтому читаем обе ветки, а при включении снимаем и отметку.

use serde::Serialize;
use tauri::command;

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const NAME: &str = "KVT";
/// Запуск без окна (автозапуск).
pub const TRAY_FLAG: &str = "--tray";

/// Что сейчас в автозагрузке Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutostartState {
    /// Windows запустит этот kvt.exe при входе.
    On,
    /// Записи нет.
    Off,
    /// Запись наша, но её выключили в «Диспетчере задач» или «Параметрах».
    Blocked,
    /// В автозагрузке другой kvt.exe (вторая установка или сборка для разработки).
    Other,
}

fn command_line() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| {
        crate::errors::io(
            kvt_core::i18n::tr("Не удалось найти kvt.exe", "Couldn't find kvt.exe"),
            &e,
        )
    })?;
    Ok(format!("\"{}\" {TRAY_FLAG}", exe.display()))
}

/// Отметка `StartupApproved`: 12 байт, младший бит первого — «выключено»
/// (02/06 — разрешено, 03/07 — запрещено). Нет отметки или она пустая — разрешено.
fn approved(mark: Option<&[u8]>) -> bool {
    mark.and_then(|m| m.first()).map_or(true, |b| b & 1 == 0)
}

fn classify(run: Option<&str>, ours: &str, mark: Option<&[u8]>) -> AutostartState {
    match run {
        None => AutostartState::Off,
        Some(current) if !current.trim().eq_ignore_ascii_case(ours) => AutostartState::Other,
        Some(_) if !approved(mark) => AutostartState::Blocked,
        Some(_) => AutostartState::On,
    }
}

/// Состояние автозапуска именно этого kvt.exe.
#[command]
pub fn autostart_state() -> Result<AutostartState, String> {
    let ours = command_line()?;
    let run = crate::winreg::get_string(RUN, NAME);
    let mark = crate::winreg::get_binary(APPROVED, NAME);
    Ok(classify(run.as_deref(), &ours, mark.as_deref()))
}

#[command]
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let result = if enabled {
        crate::winreg::set_string(RUN, NAME, &command_line()?)
    } else {
        crate::winreg::delete_value(RUN, NAME)
    }
    // Отметка Windows переживает удаление записи: без этого включённый снова
    // автозапуск остался бы запрещённым «Диспетчером задач».
    .and_then(|()| crate::winreg::delete_value(APPROVED, NAME));
    result.map_err(|e| {
        crate::errors::io(
            kvt_core::i18n::tr(
                "Не удалось изменить автозапуск",
                "Couldn't change autostart",
            ),
            &e,
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = r#""C:\Program Files\KVT\kvt.exe" --tray"#;

    #[test]
    fn our_entry_without_mark_is_on() {
        assert_eq!(classify(Some(OURS), OURS, None), AutostartState::On);
        // Регистр пути в Windows не важен; пробелы по краям оставляет ручная правка.
        let upper = OURS.to_uppercase();
        assert_eq!(classify(Some(&upper), OURS, None), AutostartState::On);
        assert_eq!(
            classify(Some(&format!(" {OURS} ")), OURS, None),
            AutostartState::On
        );
    }

    #[test]
    fn no_entry_is_off() {
        assert_eq!(classify(None, OURS, None), AutostartState::Off);
        // Отметка без записи ничего не включает.
        assert_eq!(
            classify(None, OURS, Some(&[2, 0, 0, 0])),
            AutostartState::Off
        );
    }

    #[test]
    fn task_manager_mark_blocks() {
        let disabled = [3u8, 0, 0, 0, 0x7D, 0x85, 0xB4, 0xDC, 0x7D, 0x22, 0xDB, 0x01];
        assert_eq!(
            classify(Some(OURS), OURS, Some(&disabled)),
            AutostartState::Blocked
        );
        assert_eq!(
            classify(Some(OURS), OURS, Some(&[7, 0, 0, 0])),
            AutostartState::Blocked
        );
        assert_eq!(
            classify(Some(OURS), OURS, Some(&[2; 12])),
            AutostartState::On
        );
        assert_eq!(
            classify(Some(OURS), OURS, Some(&[6, 0])),
            AutostartState::On
        );
        // Пустое или битое значение — Windows считает разрешённым.
        assert_eq!(classify(Some(OURS), OURS, Some(&[])), AutostartState::On);
    }

    #[test]
    fn other_copy_is_reported() {
        let dev = r#""C:\src\KVT\target\debug\kvt.exe" --tray"#;
        assert_eq!(classify(Some(dev), OURS, None), AutostartState::Other);
        // Без ключа --tray окно открывалось бы при каждом входе — тоже не наша запись.
        let bare = r#""C:\Program Files\KVT\kvt.exe""#;
        assert_eq!(classify(Some(bare), OURS, None), AutostartState::Other);
        assert_eq!(classify(Some(""), OURS, None), AutostartState::Other);
    }
}
