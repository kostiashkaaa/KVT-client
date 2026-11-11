//! Сервер named pipe службы.
//!
//! - права на pipe: только SYSTEM, администраторы и интерактивные пользователи;
//! - только локальные клиенты;
//! - клиент должен быть `kvt.exe` из каталога службы (Program Files в установке,
//!   target\debug при разработке) — чужая программа управлять VPN не сможет;
//! - у установленной службы SHA-256 клиента сверяется с манифестом установки;
//! - кадры с ограничением длины, неизвестные команды отвергаются.
//!
//! TODO(этап 5): дополнительно проверять Authenticode-подпись клиента.

use crate::handler::{self, State};
use crate::win;
use kvt_core::ipc::{self, Request, Response, ServiceStatus, PIPE_NAME};
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
    // Манифест сверяется только у установленной службы: при разработке рядом может
    // стоять установленный KVT со своим манифестом, а kvt.exe из сборки — другой.
    let manifest =
        crate::manifest::installed(&allowed_dir).then(crate::manifest::Verifier::default);
    let snapshot = Arc::new(std::sync::Mutex::new(Response::Status {
        status: ServiceStatus::Disconnected,
        session: None,
    }));
    // Первый экземпляр: имя уже занято — значит, работает другая служба KVT.
    let mut server = win::create_pipe(PIPE_NAME, true).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow::anyhow!(
                "pipe службы уже занят другим процессом — запущена ещё одна служба KVT \
                 (например, kvt-service --console из сборки)"
            )
        } else {
            e.into()
        }
    })?;
    tracing::info!(pipe = PIPE_NAME, "служба слушает");

    loop {
        let connected = tokio::select! {
            res = server.connect() => res,
            _ = shutdown.changed() => break,
        };
        if let Err(e) = connected {
            // Клиент закрылся, не дождавшись приёма (ERROR_NO_DATA и т. п.). Выход из
            // цикла остановил бы службу вместе с ядром и kill switch — а вызвать это
            // может любая программа пользователя. Пересоздаём экземпляр и ждём дальше.
            tracing::warn!(error = %e, "сбой приёма клиента pipe");
            drop(server);
            server = recreate_pipe(&mut shutdown).await?;
            continue;
        }
        let client = server;
        server = recreate_pipe(&mut shutdown).await?;

        match win::pipe_client_image(&client) {
            Ok(image)
                if is_trusted_client(&image, &allowed_dir)
                    && manifest.as_ref().map_or(true, |m| m.check(&image)) =>
            {
                tracing::debug!(image = %image.display(), "клиент принят");
                let state = Arc::clone(&state);
                let snapshot = Arc::clone(&snapshot);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client, state, snapshot).await {
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

/// Новый экземпляр pipe. Временный сбой (нехватка ресурсов) не должен
/// останавливать службу: несколько попыток с паузой.
async fn recreate_pipe(shutdown: &mut watch::Receiver<bool>) -> anyhow::Result<NamedPipeServer> {
    let mut attempt = 0;
    loop {
        match win::create_pipe(PIPE_NAME, false) {
            Ok(server) => return Ok(server),
            Err(e) if attempt < 20 && !*shutdown.borrow() => {
                attempt += 1;
                tracing::warn!(error = %e, attempt, "не удалось создать экземпляр pipe");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
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

/// Последний известный статус. Отдаётся на Status, пока другая команда держит
/// состояние (подключение качает списки, обновление zapret — архив): иначе окно,
/// трей и автопереключение висели бы до её конца, а «Подключение…» не было бы видно.
type Snapshot = Arc<std::sync::Mutex<Response>>;

fn set_snapshot(snapshot: &Snapshot, response: Response) {
    if let Ok(mut s) = snapshot.lock() {
        *s = response;
    }
}

async fn handle_client(
    mut pipe: NamedPipeServer,
    state: Arc<Mutex<State>>,
    snapshot: Snapshot,
) -> anyhow::Result<()> {
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
            // Сверка версии не зависит от состояния.
            Ok(request @ Request::Hello { .. }) => handler::hello(&request),
            Ok(Request::Status) => match state.try_lock() {
                Ok(mut guard) => {
                    let response = handler::handle(&mut guard, Request::Status).await;
                    set_snapshot(&snapshot, response.clone());
                    response
                }
                Err(_) => snapshot
                    .lock()
                    .map(|s| s.clone())
                    .unwrap_or(Response::Status {
                        status: ServiceStatus::Connecting,
                        session: None,
                    }),
            },
            Ok(request) => {
                if matches!(request, Request::Connect(_) | Request::StartZapret(_)) {
                    set_snapshot(
                        &snapshot,
                        Response::Status {
                            status: ServiceStatus::Connecting,
                            session: None,
                        },
                    );
                }
                let mut guard = state.lock().await;
                let response = handler::handle(&mut guard, request).await;
                set_snapshot(&snapshot, guard.status_response());
                response
            }
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
