//! Сервер named pipe службы.
//!
//! - права на pipe: только SYSTEM, администраторы и интерактивные пользователи;
//! - только локальные клиенты;
//! - клиент должен быть `kvt.exe` из каталога службы (Program Files в установке,
//!   target\debug при разработке) — чужая программа управлять VPN не сможет;
//! - кадры с ограничением длины, неизвестные команды отвергаются.
//!
//! TODO(этап 5): дополнительно проверять Authenticode-подпись клиента.

use crate::handler::{self, State};
use crate::win;
use kvt_core::ipc::{self, Request, Response, PIPE_NAME};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::{watch, Mutex};

pub async fn serve(state: State, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let state = Arc::new(Mutex::new(state));
    let allowed_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let mut server = win::create_pipe(PIPE_NAME, true)?;
    tracing::info!(pipe = PIPE_NAME, "служба слушает");

    loop {
        tokio::select! {
            res = server.connect() => res?,
            _ = shutdown.changed() => break,
        }
        let client = server;
        server = win::create_pipe(PIPE_NAME, false)?;

        match win::pipe_client_image(&client) {
            Ok(image) if is_trusted_client(&image, &allowed_dir) => {
                tracing::debug!(image = %image.display(), "клиент принят");
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client, state).await {
                        tracing::warn!(error = %e, "клиент отключён с ошибкой");
                    }
                });
            }
            Ok(image) => tracing::warn!(image = %image.display(), "отклонён чужой клиент"),
            Err(e) => tracing::warn!(error = %e, "не удалось определить клиента"),
        }
    }
    state.lock().await.shutdown().await;
    Ok(())
}

fn is_trusted_client(image: &Path, allowed_dir: &Path) -> bool {
    let same_dir = image.parent().map(normalize) == Some(normalize(allowed_dir));
    let is_app = image
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("kvt.exe"));
    same_dir && is_app
}

fn normalize(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

async fn handle_client(mut pipe: NamedPipeServer, state: Arc<Mutex<State>>) -> anyhow::Result<()> {
    loop {
        let mut header = [0u8; 4];
        if pipe.read_exact(&mut header).await.is_err() {
            return Ok(()); // клиент закрыл соединение
        }
        let len = ipc::frame_len(header)?;
        let mut body = vec![0u8; len];
        pipe.read_exact(&mut body).await?;

        let response = match ipc::decode::<Request>(&body) {
            // Пинг идёт секунды и состояния не трогает: не держим блокировку,
            // чтобы окно тем временем получало статус.
            Ok(Request::Ping { targets }) => crate::net::ping(targets).await,
            Ok(request) => handler::handle(&mut *state.lock().await, request).await,
            Err(_) => Response::Error {
                message: "неизвестная команда".into(),
            },
        };
        pipe.write_all(&ipc::encode(&response)?).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_kvt_from_service_dir_is_trusted() {
        let dir = Path::new(r"C:\Program Files\KVT");
        assert!(is_trusted_client(
            Path::new(r"C:\Program Files\KVT\kvt.exe"),
            dir
        ));
        assert!(is_trusted_client(
            Path::new(r"c:\program files\kvt\KVT.EXE"),
            dir
        ));
        assert!(!is_trusted_client(
            Path::new(r"C:\Users\x\Downloads\kvt.exe"),
            dir
        ));
        assert!(!is_trusted_client(
            Path::new(r"C:\Program Files\KVT\evil.exe"),
            dir
        ));
    }
}
