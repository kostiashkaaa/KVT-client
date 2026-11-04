//! Протокол между приложением и службой. Служба принимает только эти
//! типизированные команды: никаких путей, аргументов командной строки и сырых
//! JSON-конфигов — конфиг ядра служба генерирует сама из `ConnectPlan`.
//!
//! Кадр: 4 байта длины (little-endian) + JSON.

use crate::compile::DnsPlan;
use crate::core_select::CoreKind;
use crate::model::Server;
use crate::routing::RoutingPlan;
use crate::zapret::{GameFilter, Strategy};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PIPE_NAME: &str = r"\\.\pipe\kvt-service";
pub const PROTOCOL_VERSION: u32 = 3;
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Hello {
        protocol_version: u32,
    },
    Status,
    Connect(Box<ConnectPlan>),
    /// Только zapret, без VPN.
    StartZapret(Box<ZapretPlan>),
    Disconnect,
    /// Стратегии из комплекта zapret, который лежит рядом со службой.
    ZapretStrategies,
    /// Другие обходы блокировок, которые мешают zapret KVT.
    ZapretConflicts,
    /// Остановить найденные конфликты (только остановить, ничего не удаляя).
    StopConflicts,
    /// Версия и исправность комплекта zapret, драйвер WinDivert.
    ZapretInfo,
    /// Обновить стратегии и списки из последнего релиза Flowseal.
    ZapretUpdate,
    /// Вернуть проверенный комплект, сбросить списки и переустановить драйвер.
    ZapretRepair,
    /// Журнал сетевых запросов службы (`kvt_core::netlog`).
    NetLog,
    /// Исправление из аудита ПК, которому нужны права администратора.
    AuditFix(crate::audit::ServiceFix),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverState {
    /// Драйвер ещё не устанавливался (появится при первом запуске winws).
    Missing,
    Stopped,
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZapretInfo {
    /// Версия комплекта, который сейчас используется.
    pub version: String,
    /// Версия, с которой собран KVT.
    pub bundled_version: String,
    /// Комплект обновлён кнопкой «Обновить» (иначе — из поставки KVT).
    pub updated: bool,
    /// Комплект цел: файлы на месте, хэши программ сходятся.
    pub ok: bool,
    pub problem: Option<String>,
    pub strategies: usize,
    /// Стратегии, которые не прошли белый список флагов.
    pub rejected: Vec<String>,
    pub driver: DriverState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceReport {
    pub version: String,
    /// Что-то поменялось (иначе — уже была последняя версия).
    pub changed: bool,
    /// Исполняемые файлы тоже обновились (иначе остались проверенные прежние).
    pub binaries_updated: bool,
    /// Шаги, понятные человеку.
    pub steps: Vec<String>,
}

/// Запуск zapret. Стратегия — только имя: аргументы служба берёт из своего комплекта.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZapretPlan {
    pub strategy: String,
    #[serde(default)]
    pub game_filter: GameFilter,
    /// Разрешено включить TCP timestamps, если стратегия их требует (как делает Flowseal).
    #[serde(default)]
    pub tcp_timestamps: bool,
    /// Дополнительные домены для zapret (в гибриде к ним добавляются домены из RoutingPlan).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Домены, которые zapret не трогает.
    #[serde(default)]
    pub exclude_domains: Vec<String>,
    /// Обход по IP-списку Flowseal (`ipset-all`), а не только по доменам.
    #[serde(default)]
    pub ipset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    /// Служба Windows или процесс.
    pub service: bool,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectPlan {
    pub core: CoreKind,
    pub server: Server,
    pub routing: RoutingPlan,
    pub kill_switch: bool,
    /// Служба проверяет адреса по каталогу (`DnsPlan::validate`).
    #[serde(default)]
    pub dns: DnsPlan,
    /// Гибрид: zapret для доменов слоя Zapret, остальное — через VPN.
    #[serde(default)]
    pub zapret: Option<ZapretPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Hello {
        protocol_version: u32,
        service_version: String,
    },
    Status {
        status: ServiceStatus,
    },
    Ok,
    Error {
        message: String,
    },
    Strategies {
        strategies: Vec<Strategy>,
    },
    Conflicts {
        conflicts: Vec<Conflict>,
    },
    ZapretInfo(Box<ZapretInfo>),
    Maintenance(Box<MaintenanceReport>),
    NetLog {
        events: Vec<crate::netlog::Event>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServiceStatus {
    Disconnected,
    Connecting,
    Connected {
        core: CoreKind,
    },
    /// Работает только zapret (без VPN).
    Zapret {
        strategy: String,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("кадр больше допустимого ({0} байт)")]
    TooLarge(usize),
    #[error("некорректный JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Проверяет заголовок кадра до чтения тела — длину задаёт недоверенная сторона.
pub fn frame_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

pub fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, FrameError> {
    Ok(serde_json::from_slice(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let req = Request::Hello {
            protocol_version: PROTOCOL_VERSION,
        };
        let frame = encode(&req).unwrap();
        let len = frame_len(frame[..4].try_into().unwrap()).unwrap();
        assert_eq!(len, frame.len() - 4);
        let back: Request = decode(&frame[4..]).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn oversized_header_rejected() {
        assert!(matches!(
            frame_len(u32::MAX.to_le_bytes()),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn unknown_command_rejected() {
        assert!(decode::<Request>(br#"{"cmd":"run_binary","path":"C:\\x.exe"}"#).is_err());
    }
}
