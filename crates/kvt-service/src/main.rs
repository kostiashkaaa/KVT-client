//! KVTService — тонкая привилегированная служба. Решений не принимает: получает
//! проверенный план от приложения, сама генерирует конфиг ядра и управляет
//! TUN, zapret и kill switch.
//!
//! Команды (из терминала администратора):
//!
//! - `kvt-service --console` — запуск в консоли для разработки (Ctrl+C — выход);
//! - `kvt-service install` / `uninstall` — регистрация службы Windows (установщик:
//!   автозапуск, перезапуск при сбое, манифест клиента); `stop` — остановить и
//!   дождаться (перед заменой файлов);
//! - `kvt-service update-rules --dir <каталог> [--full] [--force]` — загрузка списков.

#![cfg_attr(test, allow(clippy::unwrap_used))]

#[cfg(windows)]
mod audit;
#[cfg(windows)]
mod handler;
#[cfg(windows)]
mod logging;
#[cfg(windows)]
mod manifest;
#[cfg(windows)]
mod net;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod rules;
#[cfg(windows)]
mod session;
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
        crate::logging::init_service(false);
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "служба запускается");
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

        let result = tokio::runtime::Runtime::new()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| runtime.block_on(crate::serve(rx)));

        // Ненулевой код — для Windows это сбой: сработает перезапуск через 5/10/30 с
        // (`set_failure_actions_on_non_crash_failures`). С нулём служба осталась бы
        // остановленной до перезагрузки.
        let mut stopped = status(ServiceState::Stopped, ServiceControlAccept::empty());
        if result.is_err() {
            stopped.exit_code = ServiceExitCode::ServiceSpecific(1);
        }
        handle.set_service_status(stopped)?;
        result
    }

    /// Права на службу: стандартные плюс запуск (RP) для интерактивных пользователей —
    /// окно поднимает остановленную службу кнопкой «Запустить службу» без прав
    /// администратора. Остановить, перенастроить или удалить её они не могут.
    const SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    /// Регистрирует службу на текущий исполняемый файл (или обновляет регистрацию —
    /// установка поверх прежней версии) и запускает её. Вызывает установщик.
    pub fn install() -> anyhow::Result<()> {
        use windows_service::service::{
            ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
        };
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let exe = std::env::current_exe()?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("KVT VPN"),
            service_type: ServiceType::OWN_PROCESS,
            // После перезагрузки KVT должен подключаться без участия пользователя.
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.clone(),
            launch_arguments: vec![],
            dependencies: vec![],
            // LocalSystem: нужен для TUN, маршрутов и WFP.
            account_name: None,
            account_password: None,
        };
        // Установщик работает от администратора; WRITE_DAC (права на службу) отдельным
        // флагом в windows-service нет — он входит в ALL_ACCESS.
        let access = ServiceAccess::ALL_ACCESS;
        let service = match manager.open_service(SERVICE_NAME, access) {
            Ok(service) => {
                service.change_config(&info)?;
                service
            }
            Err(_) => manager.create_service(&info, access)?,
        };
        // Описание в «Службах» — на языке Windows того, кто ставит KVT.
        kvt_core::i18n::set(crate::win::ui_lang());
        service.set_description(kvt_core::i18n::tr(
            "Служба KVT: запуск VPN-ядер, TUN и защита от утечек",
            "KVT service: runs VPN cores, TUN and leak protection",
        ))?;
        // Отложенный запуск: не задерживает загрузку Windows, сеть к этому времени есть.
        service.set_delayed_auto_start(true)?;
        // Упала — перезапуск через 5, 10 и 30 с; счётчик сбрасывается через сутки.
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
            reboot_msg: None,
            command: None,
            actions: Some(
                [5, 10, 30]
                    .into_iter()
                    .map(|secs| ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(secs),
                    })
                    .collect(),
            ),
        })?;
        service.set_failure_actions_on_non_crash_failures(true)?;
        crate::win::set_service_sddl(service.raw_handle() as usize, SERVICE_SDDL)?;
        let dir = exe
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        crate::manifest::write(&dir)?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&OsStr>(&[])?;
        }
        println!("Служба {SERVICE_NAME} установлена и запущена.");
        Ok(())
    }

    /// Останавливает службу и ждёт остановки (до 15 с). Нет службы — не ошибка.
    /// Установщик вызывает это перед заменой файлов: работающая служба их держит.
    pub fn stop() -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let Ok(service) = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        ) else {
            return Ok(());
        };
        if service.query_status()?.current_state != ServiceState::Stopped {
            let _ = service.stop();
            for _ in 0..150 {
                if service.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Ok(())
    }

    /// Удаляет службу, драйвер WinDivert (если им не пользуется чужой winws) и
    /// манифест. Фильтры WFP динамические — их снимает уже остановка службы.
    pub fn uninstall() -> anyhow::Result<()> {
        stop()?;
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        if let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE) {
            service.delete()?;
        }
        match crate::supervisor::Paths::standard() {
            Ok(paths) => {
                if let Err(e) = crate::zapret::remove_driver_if_unused(&paths) {
                    eprintln!("Драйвер WinDivert не удалён: {e}");
                }
            }
            Err(e) => eprintln!("Каталоги службы не найдены: {e}"),
        }
        let _ = std::fs::remove_file(crate::supervisor::data_dir().join("manifest.json"));
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
    let mut supervisor = supervisor::Supervisor::new(paths);
    // Раньше pipe: пока окно не подключилось, интернет уже закрыт.
    supervisor.restore_kill_switch();
    let state = handler::State::new(supervisor);
    pipe::serve(state, shutdown).await
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("update-rules") => {
            logging::init_console();
            return update_rules_cli(&args[1..]);
        }
        Some("install") => {
            logging::init_console();
            return service::install();
        }
        Some("uninstall") => {
            logging::init_console();
            return service::uninstall();
        }
        Some("stop") => {
            logging::init_console();
            return service::stop();
        }
        Some("--console") => {
            logging::init_service(true);
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
