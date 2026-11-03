//! Клиент службы KVT: одно соединение на запрос, сначала проверка версии протокола.

use kvt_core::ipc::{self, Request, Response, PIPE_NAME, PROTOCOL_VERSION};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_PIPE_BUSY: i32 = 231;

async fn open() -> Result<NamedPipeClient, String> {
    for _ in 0..20 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err("Служба KVT не запущена. Для разработки: запустите \
                            `kvt-service --console` в терминале администратора."
                    .into())
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                return Err("Нет доступа к службе KVT".into())
            }
            Err(e) => return Err(format!("Не удалось связаться со службой: {e}")),
        }
    }
    Err("Служба KVT занята — попробуйте ещё раз".into())
}

async fn exchange(pipe: &mut NamedPipeClient, request: &Request) -> Result<Response, String> {
    let frame = ipc::encode(request).map_err(|e| e.to_string())?;
    pipe.write_all(&frame).await.map_err(|e| e.to_string())?;
    let mut header = [0u8; 4];
    pipe.read_exact(&mut header)
        .await
        .map_err(|_| "Служба закрыла соединение".to_string())?;
    let len = ipc::frame_len(header).map_err(|e| e.to_string())?;
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body)
        .await
        .map_err(|e| e.to_string())?;
    ipc::decode(&body).map_err(|e| e.to_string())
}

pub async fn call(request: Request) -> Result<Response, String> {
    let mut pipe = open().await?;
    match exchange(
        &mut pipe,
        &Request::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await?
    {
        Response::Hello { .. } => {}
        Response::Error { message } => return Err(message),
        _ => return Err("Неожиданный ответ службы".into()),
    }
    exchange(&mut pipe, &request).await
}
