//! KVTService — тонкая привилегированная служба. Решений не принимает: получает
//! проверенный план от приложения, сама генерирует конфиг ядра и управляет
//! TUN, zapret и kill switch.
//!
//! Команды (из терминала администратора):
//!
//! - `kvt-service --console` — запуск в консоли для разработки (Ctrl+C — выход);
//! - `kvt-service install` / `uninstall` — регистрация службы Windows;
//! - `kvt-service update-rules --dir <каталог> [--full] [--force]` — загрузка списков.

#![cfg_attr(test, allow(clippy::unwrap_used))]

#[cfg(windows)]
mod audit;
#[cfg(windows)]
mod handler;
#[cfg(windows)]
mod net;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod rules;
#[cfg(windows)]
mod supervisor;
#[cfg(windows)]
mod wfp;
#[cfg(windows)]
mod win;
mod zapret;

#[cfg(windows)]
mod service {
    use std::ffi::{OsStr, OsString};
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const SERVICE_NAME: &str = "KVTService";

    define_windows_service!(ffi_service_main, service_main);

    pub fn start() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run() {
            tracing::error!(error = %e, "служба завершилась с ошибкой");
        }
    }

    fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }

    fn run() -> anyhow::Result<()> {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ))?;

        let result = tokio::runtime::Runtime::new()?.block_on(crate::serve(rx));

        handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
        result
    }

    /// Регистрирует службу на текущий исполняемый файл (запуск вручную —
    /// приложение стартует её при подключении, этап 5 переведёт на автозапуск).
    pub fn install() -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("KVT VPN"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![],
            dependencies: vec![],
            // LocalSystem: нужен для TUN, маршрутов и WFP.
            account_name: None,
            account_password: None,
        };
        let service =
            manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
        service.set_description("Служба KVT: запуск VPN-ядер, TUN и защита от утечек")?;
        service.start::<&OsStr>(&[])?;
        println!("Служба {SERVICE_NAME} установлена и запущена.");
        Ok(())
    }

    pub fn uninstall() -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )?;
        if service.query_status()?.current_state != ServiceState::Stopped {
            let _ = service.stop();
            for _ in 0..50 {
                if service.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        service.delete()?;
        println!("Служба {SERVICE_NAME} удалена.");
        Ok(())
    }
}

#[cfg(windows)]
async fn serve(shutdown: tokio::sync::watch::Receiver<bool>) -> anyhow::Result<()> {
    let paths = supervisor::Paths::standard()?;
    if !win::is_elevated() {
        tracing::warn!("служба запущена без прав администратора — подключение работать не будет");
    }
    tracing::info!(cores = %paths.cores.display(), rules = %paths.rules.display(), "каталоги");
    let state = handler::State::new(supervisor::Supervisor::new(paths));
    pipe::serve(state, shutdown).await
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("update-rules") => return update_rules_cli(&args[1..]),
        Some("install") => return service::install(),
        Some("uninstall") => return service::uninstall(),
        Some("--console") => {
            let (tx, rx) = tokio::sync::watch::channel(false);
            return tokio::runtime::Runtime::new()?.block_on(async move {
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                serve(rx).await
            });
        }
        _ => {}
    }
    service::start()?;
    Ok(())
}

/// Загрузка списков для разработки (служба делает то же самое сама при подключении).
#[cfg(windows)]
fn update_rules_cli(args: &[String]) -> anyhow::Result<()> {
    use kvt_core::core_select::CoreKind;
    use kvt_core::routing::presets::ListMode;

    let dir = args
        .iter()
        .position(|a| a == "--dir")
        .and_then(|i| args.get(i + 1))
        .ok_or_else(|| anyhow::anyhow!("укажите --dir <каталог>"))?;
    let mode = if args.iter().any(|a| a == "--full") {
        ListMode::Full
    } else {
        ListMode::Compact
    };
    let force = args.iter().any(|a| a == "--force");

    let report = tokio::runtime::Runtime::new()?.block_on(rules::update(
        std::path::Path::new(dir),
        mode,
        &[CoreKind::Xray, CoreKind::SingBox],
        force,
    ))?;
    for f in &report.updated {
        println!("обновлён   {f}");
    }
    for f in &report.unchanged {
        println!("без изменений {f}");
    }
    for s in &report.not_due {
        println!("пропущен источник {s}: проверка была недавно (--force, чтобы проверить сейчас)");
    }
    for (f, e) in &report.failed {
        eprintln!("ОШИБКА     {f}: {e}");
    }
    anyhow::ensure!(report.failed.is_empty(), "не все списки обновлены");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("KVTService работает только в Windows");
}
