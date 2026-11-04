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
                return Err(crate::errors::NO_SERVICE.into())
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                return Err(crate::errors::logged(
                    "Служба KVT не пустила это окно: она принимает команды только от KVT из папки установки. Запустите KVT из меню «Пуск» или переустановите его.",
                    e,
                ))
            }
            Err(e) => {
                return Err(crate::errors::logged(
                    "Не удалось связаться со службой KVT. Повторите через несколько секунд.",
                    e,
                ))
            }
        }
    }
    Err("Служба KVT занята — повторите через несколько секунд.".into())
}

const BROKEN: &str =
    "Связь со службой KVT прервалась. Повторите; если не выйдет — перезагрузите компьютер.";

async fn exchange(pipe: &mut NamedPipeClient, request: &Request) -> Result<Response, String> {
    let frame = ipc::encode(request).map_err(|e| crate::errors::logged(BROKEN, e))?;
    pipe.write_all(&frame)
        .await
        .map_err(|e| crate::errors::logged(BROKEN, e))?;
    let mut header = [0u8; 4];
    pipe.read_exact(&mut header)
        .await
        .map_err(|e| crate::errors::logged(BROKEN, e))?;
    let len = ipc::frame_len(header).map_err(|e| crate::errors::logged(BROKEN, e))?;
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body)
        .await
        .map_err(|e| crate::errors::logged(BROKEN, e))?;
    ipc::decode(&body).map_err(|e| crate::errors::logged(crate::errors::UNEXPECTED, e))
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
        _ => return Err(crate::errors::UNEXPECTED.into()),
    }
    exchange(&mut pipe, &request).await
}
