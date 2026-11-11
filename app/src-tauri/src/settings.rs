//! `settings.json`: выбор пользователя (сервер, режим, kill switch, маршрутизация,
//! DNS, профили сетей, zapret). У файла есть версия схемы и переносы между
//! версиями, а нечитаемый файл не сбрасывается молча:
//!
//! - битый JSON — файл сохраняется рядом как `settings.bad.json`, работа идёт с
//!   настройками по умолчанию, пользователь видит сообщение;
//! - одно поле не того вида — сбрасывается только оно, остальные (например,
//!   kill switch) сохраняются; копия исходного файла — тоже в `settings.bad.json`.

use crate::Choice;
use serde_json::{Map, Value};
use std::path::Path;

/// Текущая версия схемы.
pub const VERSION: u64 = 1;
const FILE: &str = "settings.json";
const BAD: &str = "settings.bad.json";

pub struct Loaded {
    pub choice: Choice,
    /// Сообщение для пользователя, если с файлом было что-то не так.
    pub notice: Option<String>,
}

enum Parsed {
    Ok(Choice),
    /// Часть полей не прочиталась — названия для пользователя.
    Partial(Choice, Vec<String>),
    Broken,
}

pub fn load(dir: &Path) -> Loaded {
    let path = dir.join(FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Loaded {
                choice: Choice::default(),
                notice: None,
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "settings.json не читается");
            return Loaded {
                choice: Choice::default(),
                notice: Some(
                    kvt_core::i18n::tr(
                        "Не удалось открыть файл настроек — KVT работает с настройками по умолчанию. Проверьте, не блокирует ли его антивирус.",
                        "Couldn't open the settings file — KVT is using default settings. Check whether antivirus is blocking it.",
                    )
                    .into(),
                ),
            };
        }
    };
    match parse(&bytes) {
        Parsed::Ok(choice) => Loaded {
            choice,
            notice: None,
        },
        Parsed::Partial(choice, lost) => {
            set_aside(dir);
            tracing::warn!(?lost, "часть настроек не прочиталась");
            Loaded {
                choice,
                notice: Some(kvt_core::trf!(
                    "Часть настроек не прочиталась и сброшена: {}. Остальные на месте. Исходный файл сохранён как {BAD}.",
                    "Some settings couldn't be read and were reset: {}. The rest are intact. The original file was saved as {BAD}.",
                    lost.join(", ")
                )),
            }
        }
        Parsed::Broken => {
            set_aside(dir);
            tracing::error!("settings.json повреждён");
            Loaded {
                choice: Choice::default(),
                notice: Some(kvt_core::trf!(
                    "Файл настроек повреждён — KVT вернул настройки по умолчанию (kill switch, маршрутизацию, профили сетей и zapret проверьте в настройках). Исходный файл сохранён как {BAD}.",
                    "The settings file is damaged — KVT restored the defaults (check the kill switch, routing, network profiles and zapret in settings). The original file was saved as {BAD}."
                )),
            }
        }
    }
}

fn set_aside(dir: &Path) {
    if let Err(e) = std::fs::copy(dir.join(FILE), dir.join(BAD)) {
        tracing::warn!(error = %e, "копия повреждённых настроек не сохранилась");
    }
}

fn parse(bytes: &[u8]) -> Parsed {
    let Ok(Value::Object(mut map)) = serde_json::from_slice::<Value>(bytes) else {
        return Parsed::Broken;
    };
    let version = map.get("version").and_then(Value::as_u64).unwrap_or(0);
    if version > VERSION {
        // Файл от более новой версии KVT: неизвестные поля просто не читаются.
        tracing::warn!(version, "настройки от более новой версии KVT");
    } else {
        migrate(&mut map, version);
    }
    match serde_json::from_value::<Choice>(Value::Object(map.clone())) {
        Ok(choice) => Parsed::Ok(choice),
        Err(_) => salvage(map),
    }
}

/// Переносы между версиями схемы — по шагу за раз.
fn migrate(map: &mut Map<String, Value>, from: u64) {
    if from < 1 {
        // 0 → 1: файл без версии (до 5.4). Поля те же; номер сервера `serverIndex`
        // переводится в ключ при запуске (`migrate_choice`), когда известны серверы.
    }
    map.insert("version".into(), VERSION.into());
}

/// Читает поля по одному: что не подошло, остаётся по умолчанию.
fn salvage(map: Map<String, Value>) -> Parsed {
    let Ok(Value::Object(mut good)) = serde_json::to_value(Choice::default()) else {
        return Parsed::Broken;
    };
    let mut lost = Vec::new();
    for (key, value) in map {
        let mut candidate = good.clone();
        candidate.insert(key.clone(), value);
        if serde_json::from_value::<Choice>(Value::Object(candidate.clone())).is_ok() {
            good = candidate;
        } else {
            lost.push(title(&key));
        }
    }
    match serde_json::from_value::<Choice>(Value::Object(good)) {
        Ok(choice) if lost.is_empty() => Parsed::Ok(choice),
        Ok(choice) => Parsed::Partial(choice, lost),
        Err(_) => Parsed::Broken,
    }
}

/// Название поля для пользователя.
fn title(key: &str) -> String {
    use kvt_core::i18n::tr;
    match key {
        "server" => tr("выбранный сервер", "selected server"),
        "mode" => tr("режим", "mode"),
        "killSwitch" => "kill switch",
        "routing" => tr("маршрутизация", "routing"),
        "dns" => "DNS",
        "autoSwitch" => tr("автопереключение", "auto-switch"),
        "networks" => tr("профили сетей", "network profiles"),
        "zapret" => tr("настройки zapret", "zapret settings"),
        "recent" => tr("недавние серверы", "recent servers"),
        "notifications" => tr("уведомления", "notifications"),
        "connectOnStart" => tr("подключение при запуске", "connect on startup"),
        "checkUpdates" => tr("проверка новой версии", "update check"),
        "autostartOffered" => tr("автозапуск", "autostart"),
        "onboarded" => tr("подсказки первого запуска", "first-run tips"),
        "language" => tr("язык", "language"),
        other => other,
    }
    .into()
}

pub fn save(dir: &Path, choice: &Choice) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| {
        crate::errors::io(
            kvt_core::i18n::tr("Не удалось сохранить настройки", "Couldn't save settings"),
            &e,
        )
    })?;
    let mut value = serde_json::to_value(choice).map_err(|_| crate::errors::state_text())?;
    if let Value::Object(map) = &mut value {
        map.insert("version".into(), VERSION.into());
    }
    let bytes = serde_json::to_vec_pretty(&value).map_err(|_| crate::errors::state_text())?;
    // Сохраняют окно, трей, автопереключение и профиль сети — из разных потоков.
    // Общий .tmp при одновременной записи давал бы битый JSON (хвост длинной
    // записи после короткой), а битый файл при запуске сбросил бы kill switch.
    static SAVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SAVE.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = dir.join(format!("{FILE}.tmp"));
    std::fs::write(&tmp, bytes)
        .and_then(|()| std::fs::rename(&tmp, dir.join(FILE)))
        .map_err(|e| {
            crate::errors::io(
                kvt_core::i18n::tr("Не удалось сохранить настройки", "Couldn't save settings"),
                &e,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kvt-settings-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_silent_default() {
        let dir = tmp("missing");
        let loaded = load(&dir);
        assert!(loaded.notice.is_none());
        assert!(!loaded.choice.kill_switch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrip_with_version() {
        let dir = tmp("roundtrip");
        let choice = Choice {
            kill_switch: true,
            ..Choice::default()
        };
        save(&dir, &choice).unwrap();
        let raw: Value = serde_json::from_slice(&std::fs::read(dir.join(FILE)).unwrap()).unwrap();
        assert_eq!(raw["version"], VERSION);
        let loaded = load(&dir);
        assert!(loaded.notice.is_none());
        assert!(loaded.choice.kill_switch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_without_version_is_migrated() {
        let dir = tmp("v0");
        std::fs::write(
            dir.join(FILE),
            br#"{"killSwitch":true,"mode":"hybrid","serverIndex":2}"#,
        )
        .unwrap();
        let loaded = load(&dir);
        assert!(loaded.notice.is_none());
        assert!(loaded.choice.kill_switch);
        assert_eq!(loaded.choice.mode.as_deref(), Some("hybrid"));
        assert_eq!(loaded.choice.server_index, Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_file_is_set_aside_with_notice() {
        let dir = tmp("broken");
        std::fs::write(dir.join(FILE), b"{ \"killSwitch\": tru").unwrap();
        let loaded = load(&dir);
        assert!(loaded.notice.unwrap().contains(BAD));
        assert!(dir.join(BAD).exists());
        assert!(!loaded.choice.kill_switch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_bad_field_does_not_reset_the_others() {
        let dir = tmp("partial");
        std::fs::write(
            dir.join(FILE),
            br#"{"version":1,"killSwitch":true,"networks":"not a list","autoSwitch":false}"#,
        )
        .unwrap();
        let loaded = load(&dir);
        let notice = loaded.notice.unwrap();
        assert!(notice.contains("профили сетей"), "{notice}");
        assert!(loaded.choice.kill_switch);
        assert!(!loaded.choice.auto_switch);
        assert!(loaded.choice.networks.is_empty());
        assert!(dir.join(BAD).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
