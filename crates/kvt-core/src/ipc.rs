//! Протокол между приложением и службой. Служба принимает только эти
//! типизированные команды: никаких путей, аргументов командной строки и сырых
//! JSON-конфигов — конфиг ядра служба генерирует сама из `ConnectPlan`.
//!
//! Кадр: 4 байта длины (little-endian) + JSON.

use crate::core_select::CoreKind;
use crate::model::Server;
use crate::routing::RoutingPlan;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PIPE_NAME: &str = r"\\.\pipe\kvt-service";
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Hello { protocol_version: u32 },
    Status,
    Connect(Box<ConnectPlan>),
    Disconnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectPlan {
    pub core: CoreKind,
    pub server: Server,
    pub routing: RoutingPlan,
    pub kill_switch: bool,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServiceStatus {
    Disconnected,
    Connecting,
    Connected { core: CoreKind },
    Failed { reason: String },
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
