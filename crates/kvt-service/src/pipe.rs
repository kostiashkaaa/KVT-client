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
use crate::supervisor::Shared;
use crate::win;
use kvt_core::ipc::{self, Request, Response, ServiceStatus, PIPE_NAME};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::{watch, Mutex};

pub async fn serve(state: State, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let shared = state.shared();
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
    let cancel: Cancel = Arc::new(watch::channel(0).0);
    let reconnecting = Arc::new(AtomicBool::new(false));
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
                let ctx = Context {
                    state: Arc::clone(&state),
                    shared: shared.clone(),
                    snapshot: Arc::clone(&snapshot),
                    cancel: Arc::clone(&cancel),
                    reconnecting: Arc::clone(&reconnecting),
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client, ctx).await {
                        tracing::warn!(error = %e, "клиент отключён с ошибкой");
                    }
                });
            }
            Ok(image) => tracing::warn!(image = %image.display(), "отклонён чужой клиент"),
            Err(e) => tracing::warn!(error = %e, "не удалось определить клиента"),
        }
    }
    // Остановка службы прерывает запуск и переподключение, как «Отключить»: иначе она
    // ждала бы, пока подключение докачает списки (минуты), а установщик тем временем
    // менял бы файлы работающей службы.
    cancel.send_modify(|n| *n = n.wrapping_add(1));
    match tokio::time::timeout(STOP_WAIT, state.lock()).await {
        Ok(mut guard) => guard.shutdown().await,
        // Команду без отмены (переустановка zapret качает архив) не ждём: процесс
        // завершится, ядро и winws закроются вместе с job, фильтры WFP — вместе с
        // сессией. Отметку kill switch стираем: её восстановление — только после сбоя.
        Err(_) => {
            tracing::warn!(
                "команда не завершилась за {STOP_WAIT:?} — служба останавливается без неё"
            );
            shared.forget_kill_switch();
        }
    }
    Ok(())
}

/// Сколько остановка службы ждёт текущую команду (после отмены запуска).
const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

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

/// Счётчик команд «Отключить»: запуск следит, не выросло ли число с его прихода.
type Cancel = Arc<watch::Sender<u64>>;

/// Всё, что делят между собой клиенты pipe.
#[derive(Clone)]
struct Context {
    state: Arc<Mutex<State>>,
    /// Для команд без блокировки состояния (`handler::stateless`).
    shared: Shared,
    snapshot: Snapshot,
    cancel: Cancel,
    /// Переподключение по ошибке ядра уже запущено (`spawn_reconnect`).
    reconnecting: Arc<AtomicBool>,
}

impl Context {
    /// Будущее, которое завершится, когда придёт «Отключить» после этого момента.
    fn cancelled(&self) -> impl std::future::Future<Output = ()> {
        let issued = *self.cancel.borrow();
        let mut cancelled = self.cancel.subscribe();
        async move {
            // Ошибка — отправитель закрыт, служба останавливается.
            let _ = cancelled.wait_for(|n| *n != issued).await;
        }
    }

    fn connecting(&self) {
        set_snapshot(
            &self.snapshot,
            Response::Status {
                status: ServiceStatus::Connecting,
                session: None,
            },
        );
    }

    /// VPN работает по последнему известному статусу.
    fn vpn_running(&self) -> bool {
        self.snapshot.lock().is_ok_and(|s| {
            matches!(
                *s,
                Response::Status {
                    status: ServiceStatus::Connected { .. },
                    ..
                }
            )
        })
    }
}

async fn handle_client(mut pipe: NamedPipeServer, ctx: Context) -> anyhow::Result<()> {
    loop {
        let mut header = [0u8; 4];
        if pipe.read_exact(&mut header).await.is_err() {
            return Ok(()); // клиент закрыл соединение
        }
        let len = ipc::frame_len(header)?;
        let mut body = vec![0u8; len];
        pipe.read_exact(&mut body).await?;

        let response = match ipc::decode::<Request>(&body) {
            Ok(request) => match handler::stateless(&ctx.shared, request).await {
                Ok(response) => response,
                Err(Request::Status) => status(&ctx).await,
                Err(Request::ZapretUpdate) => zapret_update(&ctx).await,
                Err(request) => locked(&ctx, request).await,
            },
            Err(_) => Response::Error {
                message: kvt_core::i18n::tr("неизвестная команда", "unknown command").into(),
            },
        };
        // Ответ больше кадра — понятная ошибка, а не оборванное соединение.
        let frame = match ipc::encode(&response) {
            Ok(frame) => frame,
            Err(e) => {
                tracing::warn!(error = %e, "ответ не помещается в кадр");
                ipc::encode(&Response::Error {
                    message: kvt_core::i18n::tr(
                        "Ответ службы слишком большой. Сохраните диагностику и сообщите о проблеме.",
                        "The service's answer is too large. Save diagnostics and report the problem.",
                    )
                    .into(),
                })?
            }
        };
        pipe.write_all(&frame).await?;
    }
}

/// Статус не ждёт блокировку: пока её держит другая команда, отдаётся снимок.
/// Переподключение по ошибке ядра — отдельной задачей (`spawn_reconnect`), чтобы
/// ни статус, ни «Отключить» не ждали его десятки секунд.
async fn status(ctx: &Context) -> Response {
    let Ok(mut guard) = ctx.state.try_lock() else {
        return ctx
            .snapshot
            .lock()
            .map(|s| s.clone())
            .unwrap_or(Response::Status {
                status: ServiceStatus::Connecting,
                session: None,
            });
    };
    let response = handler::handle(&mut guard, Request::Status).await;
    set_snapshot(&ctx.snapshot, response.clone());
    if guard.reconnect_pending() {
        spawn_reconnect(ctx);
    }
    response
}

/// Отмена считается от этого момента: «Отключить», пришедшее раньше, уже остановило
/// ядро и стёрло правило ошибок, и переподключаться будет нечего.
fn spawn_reconnect(ctx: &Context) {
    if ctx.reconnecting.swap(true, Ordering::AcqRel) {
        return;
    }
    let cancelled = ctx.cancelled();
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let mut guard = ctx.state.lock().await;
        ctx.connecting();
        handler::reconnect_or_cancel(&mut guard, cancelled).await;
        set_snapshot(&ctx.snapshot, guard.status_response());
        ctx.reconnecting.store(false, Ordering::Release);
    });
}

/// «Обновить zapret»: архив качается минутами — до блокировки, иначе всё это
/// время не работали бы «Отключить» и «Подключить». Блокировка — только на установку.
async fn zapret_update(ctx: &Context) -> Response {
    match handler::fetch_zapret_update(&ctx.shared, ctx.vpn_running()).await {
        Ok(prepared) => {
            let mut guard = ctx.state.lock().await;
            let response = handler::install_zapret(&mut guard, Some(prepared)).await;
            set_snapshot(&ctx.snapshot, guard.status_response());
            response
        }
        Err(response) => response,
    }
}

/// Команды, которым нужно состояние: запуск, остановка, переустановка zapret.
async fn locked(ctx: &Context, request: Request) -> Response {
    let starts = matches!(request, Request::Connect(_) | Request::StartZapret(_));
    if starts {
        ctx.connecting();
    }
    // «Отключить» прерывает запуск и переподключение, начатые до него, — ещё до
    // блокировки, которую они держат. Запуск, пришедший позже, не отменяется.
    if matches!(request, Request::Disconnect) {
        ctx.cancel.send_modify(|n| *n = n.wrapping_add(1));
    }
    let cancelled = ctx.cancelled();
    let mut guard = ctx.state.lock().await;
    let response = if starts {
        handler::handle_or_cancel(&mut guard, request, cancelled).await
    } else {
        handler::handle(&mut guard, request).await
    };
    set_snapshot(&ctx.snapshot, guard.status_response());
    response
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
