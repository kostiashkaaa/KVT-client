//! Клиент службы KVT: одно соединение на запрос, сначала проверка версии протокола.

use kvt_core::ipc::{self, Request, Response, PIPE_NAME, PROTOCOL_VERSION};
use std::sync::atomic::{AtomicBool, Ordering};
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
                return Err(crate::errors::no_service().into())
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                return Err(crate::errors::logged(
                    kvt_core::i18n::tr(
                        "Служба KVT не пустила это окно: она принимает команды только от KVT из папки установки. Запустите KVT из меню «Пуск» или переустановите его.",
                        "The KVT service refused this window: it only accepts commands from KVT in its install folder. Start KVT from the Start menu or reinstall it.",
                    ),
                    e,
                ))
            }
            Err(e) => {
                return Err(crate::errors::logged(
                    kvt_core::i18n::tr(
                        "Не удалось связаться со службой KVT. Повторите через несколько секунд.",
                        "Couldn't reach the KVT service. Try again in a few seconds.",
                    ),
                    e,
                ))
            }
        }
    }
    Err(kvt_core::i18n::tr(
        "Служба KVT занята — повторите через несколько секунд.",
        "The KVT service is busy — try again in a few seconds.",
    )
    .into())
}

fn broken() -> &'static str {
    kvt_core::i18n::tr(
        "Связь со службой KVT прервалась. Повторите; если не выйдет — перезагрузите компьютер.",
        "Lost connection to the KVT service. Try again; if it fails, restart the computer.",
    )
}

async fn exchange(pipe: &mut NamedPipeClient, request: &Request) -> Result<Response, String> {
    let frame = ipc::encode(request).map_err(|e| crate::errors::logged(broken(), e))?;
    pipe.write_all(&frame)
        .await
        .map_err(|e| crate::errors::logged(broken(), e))?;
    let mut header = [0u8; 4];
    pipe.read_exact(&mut header)
        .await
        .map_err(|e| crate::errors::logged(broken(), e))?;
    let len = ipc::frame_len(header).map_err(|e| crate::errors::logged(broken(), e))?;
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body)
        .await
        .map_err(|e| crate::errors::logged(broken(), e))?;
    ipc::decode(&body).map_err(|e| crate::errors::logged(crate::errors::unexpected(), e))
}

/// Служба отвергла приветствие: окно и служба разных версий (прерванное обновление).
/// Тогда «Запустить службу» не поможет — окно и трей просят переустановить KVT.
static MISMATCH: AtomicBool = AtomicBool::new(false);

pub fn version_mismatch() -> bool {
    MISMATCH.load(Ordering::Relaxed)
}

/// Окно спрашивает после статуса: служба отвечает, но другой версии.
#[tauri::command]
pub fn service_mismatch() -> bool {
    version_mismatch()
}

pub async fn call(request: Request) -> Result<Response, String> {
    let mut pipe = open().await?;
    let hello = exchange(
        &mut pipe,
        &Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            lang: kvt_core::i18n::current(),
        },
    )
    .await;
    match hello {
        Ok(Response::Hello { .. }) => MISMATCH.store(false, Ordering::Relaxed),
        // Связь оборвалась — это не версия, а сбой канала.
        Err(e) if e != crate::errors::unexpected() => return Err(e),
        // Служба старше или новее: приветствие не принято или ответ не разобрался.
        _ => {
            MISMATCH.store(true, Ordering::Relaxed);
            return Err(crate::errors::version_mismatch().into());
        }
    }
    exchange(&mut pipe, &request).await
}
