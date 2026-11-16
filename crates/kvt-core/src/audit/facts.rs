//! Факты о системе, как их отдаёт скрипт сбора: типы, разбор JSON, прокси WinHTTP.
//! Выводов из фактов здесь нет — они в `analyze` и проверках `leaks`, `conflicts`,
//! `zapret`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::i18n::tr;
use crate::trf;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Facts {
    pub proxy: SystemProxy,
    /// Значение `WinHttpSettings` в Base64 (пусто — не задано).
    pub winhttp: String,
    pub teredo: Teredo,
    pub adapters: Vec<Adapter>,
    pub processes: Vec<Process>,
    pub antivirus: Vec<String>,
    pub services: Vec<Service>,
    pub autostart: Vec<Autostart>,
    pub browsers: Vec<BrowserDns>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SystemProxy {
    pub enable: i64,
    pub server: String,
    pub auto_config_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Teredo {
    #[serde(rename = "type")]
    pub kind: String,
    pub state: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Adapter {
    pub name: String,
    pub description: String,
    pub status: String,
    /// DNS, прописанный вручную (через запятую или пробел); пусто — от DHCP.
    pub static_dns: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Process {
    pub pid: u32,
    /// Имя без `.exe`, как его отдаёт `Get-Process`.
    pub name: String,
    /// Пусто, если путь недоступен (процесс другого пользователя или с правами администратора).
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Service {
    pub name: String,
    pub display_name: String,
    /// `Running`, `Stopped`…
    pub state: String,
    /// `Auto`, `Manual`, `Disabled`.
    pub start_mode: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    HkcuRun,
    HklmRun,
    HkcuStartup,
    CommonStartup,
    Task,
}

impl Location {
    /// Отключить может только служба (раздел HKLM, общая папка, задания планировщика).
    pub fn machine_wide(self) -> bool {
        !matches!(self, Location::HkcuRun | Location::HkcuStartup)
    }

    pub(super) fn title(self) -> &'static str {
        match self {
            Location::HkcuRun | Location::HklmRun => tr("автозагрузка", "Startup"),
            Location::HkcuStartup | Location::CommonStartup => {
                tr("папка автозагрузки", "Startup folder")
            }
            Location::Task => tr("планировщик заданий", "Task Scheduler"),
        }
    }
}

/// Значение `StartupApproved`, которое пишет «Диспетчер задач» при «Отключить»:
/// первый байт 03, остальное — время (необязательно).
pub const STARTUP_DISABLED: &str = "030000000000000000000000";

impl Location {
    /// Раздел `StartupApproved` для `reg.exe`; у заданий планировщика его нет.
    pub fn approved_key(self) -> Option<&'static str> {
        match self {
            Location::HkcuRun => {
                Some(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
            }
            Location::HklmRun => {
                Some(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
            }
            Location::HkcuStartup => Some(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
            ),
            Location::CommonStartup => Some(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
            ),
            Location::Task => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Autostart {
    pub location: Location,
    pub name: String,
    #[serde(default)]
    pub command: String,
    /// Уже отключено (в «Диспетчере задач» или планировщике).
    #[serde(default)]
    pub disabled: bool,
}

impl Autostart {
    /// Постоянный идентификатор записи: по нему служба находит запись сама.
    pub fn id(&self) -> String {
        let mut h = Sha256::new();
        h.update(format!(
            "{:?}\0{}\0{}",
            self.location, self.name, self.command
        ));
        h.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct BrowserDns {
    /// `chrome`, `edge`, `yandex`, `brave`, `firefox`.
    pub browser: String,
    /// Chromium: `off` / `automatic` / `secure`; Firefox: число `network.trr.mode`.
    pub mode: String,
    pub templates: String,
}

/// Ответ скрипта сбора сведений о системе не разобран.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{}", trf!(
    "не удалось разобрать сведения о системе: {}",
    "couldn't read the system information: {}",
    .0
))]
pub struct FactsError(pub String);

pub fn parse_facts(json: &str) -> Result<Facts, FactsError> {
    serde_json::from_str(json.trim().trim_start_matches('\u{feff}'))
        .map_err(|e| FactsError(e.to_string()))
}

/// Адрес прокси из `WinHttpSettings` (структура WINHTTP_PROXY_INFO в реестре):
/// 4 байта версии, 4 — счётчика, 4 — флагов (бит 2 — задан прокси), 4 — длины, строка.
pub fn winhttp_proxy(base64_value: &str) -> Option<String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(base64_value.trim())
        .ok()?;
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?))
    };
    if u32_at(8)? & 0x2 == 0 {
        return None;
    }
    let len = u32_at(12)? as usize;
    let proxy = raw.get(16..16 + len)?;
    let proxy = String::from_utf8_lossy(proxy).trim().to_owned();
    (!proxy.is_empty()).then_some(proxy)
}
