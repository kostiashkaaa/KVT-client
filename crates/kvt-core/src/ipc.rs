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
pub const PROTOCOL_VERSION: u32 = 11;
/// Сколько адресов можно пингнуть одной командой `Ping`.
pub const MAX_PING_TARGETS: usize = 1024;
pub const MAX_FRAME_LEN: usize = 1024 * 1024;
/// Ответ на `Connect` / `StartZapret`, прерванные командой `Disconnect`. Окно не
/// показывает его как ошибку: пользователь сам нажал «Отключить».
const CANCELLED_RU: &str = "Подключение отменено.";
const CANCELLED_EN: &str = "Connection cancelled.";

pub fn cancelled() -> &'static str {
    crate::i18n::tr(CANCELLED_RU, CANCELLED_EN)
}

/// Ответ службы — отмена (на любом из языков: язык мог смениться между запросами).
pub fn is_cancelled(message: &str) -> bool {
    message == CANCELLED_RU || message == CANCELLED_EN
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Hello {
        protocol_version: u32,
        /// Язык текстов, которые служба вернёт окну (ошибки, итоги).
        #[serde(default)]
        lang: crate::i18n::Lang,
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
    /// Журнал службы для экспорта диагностики (уже без секретов и адресов серверов).
    ServiceLog,
    /// Просит ли сеть войти (отель, кафе): проверка напрямую через физический
    /// адаптер, мимо туннеля и kill switch.
    CaptiveCheck,
    /// TCP-пинг серверов напрямую через физический адаптер — когда VPN подключён,
    /// пинг из окна принял бы сам TUN. `None` — не проверять (UDP-протоколы).
    /// Имена служба узнаёт через DoH, первым — резолвер `doh` (id из каталога).
    Ping {
        targets: Vec<Option<PingTarget>>,
        doh: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingTarget {
    pub host: String,
    pub port: u16,
}

/// Итог проверки сети на страницу входа.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Captive {
    /// Интернет напрямую есть.
    Online,
    /// Вместо ответа — перенаправление или чужая страница: сеть просит войти.
    Portal,
    /// Ответа нет (сети нет или проверка заблокирована).
    Offline,
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
        /// Текущий сеанс: есть, пока работает VPN или zapret.
        #[serde(default)]
        session: Option<Session>,
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
    ServiceLog {
        /// Журнал службы на диске и последние строки ядра.
        log: String,
        core: String,
    },
    Captive {
        state: Captive,
    },
    /// Результаты в порядке `targets`.
    Ping {
        results: Vec<crate::tester::QuickResult>,
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
        /// Kill switch остался включён и держит интернет закрытым: окну и трею
        /// нужна кнопка «Отключить», а не «Подключить».
        #[serde(default)]
        blocked: bool,
    },
}

/// Сеанс — от «Подключить» до «Отключить». Замена сервера, переподключение после
/// сна и смена режима его не прерывают.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// Секунды с начала сеанса (по монотонным часам службы).
    pub secs: u64,
    /// Байты, принятые и отправленные через адаптер KVT. `None` — адаптера нет
    /// (режим Zapret).
    pub rx: Option<u64>,
    pub tx: Option<u64>,
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
            lang: crate::i18n::Lang::En,
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
