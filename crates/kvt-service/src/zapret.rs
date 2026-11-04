//! winws (zapret Flowseal) в службе.
//!
//! - Аргументы — только из стратегий комплекта, через белый список
//!   `kvt_core::zapret`; от приложения приходит лишь имя стратегии.
//! - Перед запуском сверяются SHA-256 winws.exe, WinDivert и cygwin1.dll.
//! - Списки лежат в `ProgramData\KVT\zapret` (только SYSTEM и администраторы):
//!   списки Flowseal плюс свои `*-user.txt` с доменами zapret и адресами
//!   VPN-серверов, которые winws не трогает.
//! - `service.bat` не вызывается: никаких чужих служб и процессов KVT не
//!   удаляет. TCP timestamps включаются, только если это разрешено в настройках.
//!
//! Комплектов два: поставленный с KVT (рядом со службой) и обновлённый кнопкой
//! «Обновить» (`ProgramData\KVT\zapret-bundle`). Обновление берёт из релиза
//! Flowseal стратегии и списки — это данные, они проходят белый список. Исполняемые
//! файлы принимаются, только если их хэш KVT уже знает; иначе остаются прежние.

use crate::net::NetClient;
use crate::supervisor::{secure_dir, spawn_supervised, Log, Paths};
use crate::win::Job;
use kvt_core::ipc::{Conflict, DriverState, MaintenanceReport, ZapretInfo, ZapretPlan};
use kvt_core::rulesync::{sha256_hex, Http};
use kvt_core::zapret::{self, RenderContext, Strategy};
use std::net::IpAddr;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DRIVER_SERVICE: &str = "WinDivert";
const MAX_ARCHIVE: usize = 30 * 1024 * 1024;
const MAX_LIST: u64 = 5 * 1024 * 1024;
/// Файлы-«фейки» Flowseal (`*.bin`) — пакеты по несколько сотен байт.
const MAX_FAKE: u64 = 64 * 1024;

/// Службы других обходов блокировок: с ними два winws портят друг другу пакеты.
const CONFLICTING_SERVICES: &[&str] = &[
    "zapret",
    "GoodbyeDPI",
    "discordfix_zapret",
    "winws1",
    "winws2",
];
const CONFLICTING_PROCESSES: &[&str] = &["winws.exe", "goodbyedpi.exe"];

pub struct Winws {
    child: Child,
    _job: Job,
    pub strategy: String,
}

impl Winws {
    pub fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(format!("zapret остановился ({status})")),
            _ => None,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
}

fn read_version(bundle: &Path) -> String {
    std::fs::read_to_string(bundle.join("VERSION"))
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| zapret::valid_version(v))
        .unwrap_or_else(|| "неизвестна".into())
}

/// Стратегии комплекта (порядок Flowseal) и имена отвергнутых белым списком.
fn scan_strategies(bundle: &Path) -> (Vec<Strategy>, Vec<String>) {
    let mut ok = Vec::new();
    let mut rejected = Vec::new();
    let Ok(entries) = std::fs::read_dir(bundle.join("strategies")) else {
        return (ok, rejected);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bat") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|t| zapret::parse_bat(id, &t).map_err(|e| e.to_string()))
        {
            Ok(s) => ok.push(s),
            Err(e) => {
                tracing::warn!(id, %e, "стратегия отвергнута");
                rejected.push(id.to_owned());
            }
        }
    }
    zapret::sort(&mut ok);
    rejected.sort();
    (ok, rejected)
}

fn verify_binaries(bin: &Path) -> Result<(), String> {
    for name in zapret::BINARIES {
        let bytes = std::fs::read(bin.join(name)).map_err(|_| format!("нет файла {name}"))?;
        if !zapret::binary_known(name, &sha256_hex(&bytes)) {
            return Err(format!("файл {name} изменён"));
        }
    }
    Ok(())
}

/// Комплект цел: программы проверены, списки на месте, есть хоть одна стратегия.
fn check_bundle(bundle: &Path) -> Result<(Vec<Strategy>, Vec<String>), String> {
    verify_binaries(&bundle.join("bin"))?;
    if !bundle.join("lists").join("list-general.txt").exists() {
        return Err("нет списков".into());
    }
    let (ok, rejected) = scan_strategies(bundle);
    if ok.is_empty() {
        return Err("нет ни одной стратегии".into());
    }
    Ok((ok, rejected))
}

/// Комплект, которым сейчас пользуется служба: обновлённый, если он цел, иначе из поставки.
pub fn active_bundle(paths: &Paths) -> PathBuf {
    if check_bundle(&paths.zapret_update).is_ok() {
        paths.zapret_update.clone()
    } else {
        paths.zapret.clone()
    }
}

pub fn strategies(paths: &Paths) -> Vec<Strategy> {
    scan_strategies(&active_bundle(paths)).0
}

fn driver_state() -> DriverState {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let status = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service(DRIVER_SERVICE, ServiceAccess::QUERY_STATUS))
        .and_then(|s| s.query_status());
    match status {
        Err(_) => DriverState::Missing,
        Ok(s) if s.current_state == ServiceState::Running => DriverState::Running,
        Ok(_) => DriverState::Stopped,
    }
}

/// Драйвер WinDivert ставит сам winws при первом запуске; удалённый — поставится заново.
fn remove_driver() -> Result<(), String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| e.to_string())?;
    let Ok(service) = manager.open_service(
        DRIVER_SERVICE,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) else {
        return Ok(());
    };
    let _ = service.stop();
    service.delete().map_err(|e| e.to_string())
}

pub fn info(paths: &Paths) -> ZapretInfo {
    let bundle = active_bundle(paths);
    let checked = check_bundle(&bundle);
    let (strategies, rejected) = match &checked {
        Ok((ok, rejected)) => (ok.len(), rejected.clone()),
        Err(_) => (0, Vec::new()),
    };
    ZapretInfo {
        version: read_version(&bundle),
        bundled_version: read_version(&paths.zapret),
        updated: bundle == paths.zapret_update,
        ok: checked.is_ok(),
        problem: checked.err(),
        strategies,
        rejected,
        driver: driver_state(),
    }
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')'))
}

fn copy_files(
    from: &Path,
    to: &Path,
    keep: impl Fn(&str) -> bool,
    max: u64,
) -> Result<usize, String> {
    let mut n = 0;
    let Ok(entries) = std::fs::read_dir(from) else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_file() && meta.len() <= max && safe_name(name) && keep(name) {
            std::fs::copy(entry.path(), to.join(name)).map_err(|e| format!("{name}: {e}"))?;
            n += 1;
        }
    }
    Ok(n)
}

/// Собирает комплект из распакованного релиза. Стратегии — только прошедшие белый
/// список; исполняемые файлы — новые, если их хэш известен, иначе из `fallback_bin`.
/// Возвращает, обновились ли исполняемые файлы.
fn stage(
    release: &Path,
    fallback_bin: &Path,
    staging: &Path,
    version: &str,
) -> Result<bool, String> {
    for sub in ["bin", "lists", "strategies"] {
        std::fs::create_dir_all(staging.join(sub)).map_err(|e| e.to_string())?;
    }
    // Стратегии лежат в корне релиза (так у Flowseal) или в strategies/ (так у KVT).
    for dir in [release.to_path_buf(), release.join("strategies")] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let (Some(id), Some("bat")) = (
                path.file_stem().and_then(|s| s.to_str()),
                path.extension().and_then(|e| e.to_str()),
            ) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if id.starts_with("general") && zapret::parse_bat(id, &text).is_ok() {
                std::fs::write(staging.join("strategies").join(format!("{id}.bat")), text)
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    copy_files(
        &release.join("lists"),
        &staging.join("lists"),
        |n| n.ends_with(".txt") || n.ends_with(".backup"),
        MAX_LIST,
    )?;
    copy_files(
        &release.join("bin"),
        &staging.join("bin"),
        |n| n.ends_with(".bin"),
        MAX_FAKE,
    )?;

    let mut all_new = true;
    for name in zapret::BINARIES {
        let new = release.join("bin").join(name);
        let known = std::fs::read(&new).is_ok_and(|b| zapret::binary_known(name, &sha256_hex(&b)));
        let source = if known {
            new
        } else {
            all_new = false;
            fallback_bin.join(name)
        };
        std::fs::copy(&source, staging.join("bin").join(name))
            .map_err(|e| format!("{name}: {e}"))?;
    }
    for license in [
        release.join("LICENSE.txt"),
        fallback_bin.join("..").join("LICENSE.txt"),
    ] {
        if std::fs::copy(&license, staging.join("LICENSE.txt")).is_ok() {
            break;
        }
    }
    std::fs::write(staging.join("VERSION"), version).map_err(|e| e.to_string())?;
    Ok(all_new)
}

/// Системный tar.exe (bsdtar) распаковывает zip и не выходит за каталог назначения.
fn extract(archive: &Path, dest: &Path) -> Result<PathBuf, String> {
    let system =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let status = std::process::Command::new(system.join("System32").join("tar.exe"))
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("tar: {e}"))?;
    if !status.success() {
        return Err("не удалось распаковать архив".into());
    }
    // В архиве Flowseal всё лежит в одном каталоге zapret-discord-youtube-<версия>.
    let dirs: Vec<PathBuf> = std::fs::read_dir(dest)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    Ok(match dirs.as_slice() {
        [only] => only.clone(),
        _ => dest.to_path_buf(),
    })
}

fn data_dir(paths: &Paths) -> PathBuf {
    paths
        .zapret_update
        .parent()
        .map_or_else(|| paths.zapret_update.clone(), Path::to_path_buf)
}

/// Скачивает архив, сверяет SHA-256 и собирает из него комплект в `zapret-bundle`.
async fn download_bundle(
    paths: &Paths,
    url: &str,
    sha256: &str,
    version: &str,
    fallback_bin: &Path,
) -> Result<bool, String> {
    let http = NetClient::new(kvt_core::netlog::Purpose::Update).map_err(|e| e.to_string())?;
    let bytes = http.get(url, MAX_ARCHIVE).await?;
    if sha256_hex(&bytes) != sha256.to_ascii_lowercase() {
        return Err("архив не совпал с хэшем — загрузка отменена".into());
    }
    let work = data_dir(paths).join("zapret-work");
    let _ = std::fs::remove_dir_all(&work);
    secure_dir(&work)?;
    let result = (|| {
        let archive = work.join("release.zip");
        std::fs::write(&archive, &bytes).map_err(|e| e.to_string())?;
        let root = extract(&archive, &work.join("x"))?;
        let staging = data_dir(paths).join("zapret-bundle.new");
        let _ = std::fs::remove_dir_all(&staging);
        secure_dir(&staging)?;
        let binaries = stage(&root, fallback_bin, &staging, version)?;
        if let Err(e) = check_bundle(&staging) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(format!("новый комплект не прошёл проверку: {e}"));
        }
        let _ = std::fs::remove_dir_all(&paths.zapret_update);
        std::fs::rename(&staging, &paths.zapret_update).map_err(|e| e.to_string())?;
        Ok(binaries)
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

/// «Обновить»: последний релиз Flowseal. Служба перед этим останавливает winws.
pub async fn update(paths: &Paths) -> Result<MaintenanceReport, String> {
    let http = NetClient::new(kvt_core::netlog::Purpose::Update).map_err(|e| e.to_string())?;
    let release = zapret::parse_release(&http.get(zapret::RELEASES_API, 1024 * 1024).await?)?;
    let active = active_bundle(paths);
    let current = read_version(&active);
    if !zapret::newer(&release.version, &current) {
        return Ok(MaintenanceReport {
            version: current.clone(),
            changed: false,
            binaries_updated: false,
            steps: vec![format!("Установлена последняя версия Flowseal — {current}")],
        });
    }
    let binaries = download_bundle(
        paths,
        &release.zip_url,
        &release.sha256,
        &release.version,
        &active.join("bin"),
    )
    .await?;
    let (strategies, rejected) = scan_strategies(&paths.zapret_update);
    let mut steps = vec![
        format!("Скачан релиз {} (SHA-256 сверен с GitHub)", release.version),
        format!("Стратегий: {}", strategies.len()),
    ];
    if !rejected.is_empty() {
        steps.push(format!(
            "Пропущены стратегии с неизвестными флагами: {}",
            rejected.join(", ")
        ));
    }
    steps.push(if binaries {
        "winws и WinDivert — проверенные версии".into()
    } else {
        "winws и WinDivert в этом релизе новые — KVT оставил проверенные прежние; новые придут с обновлением KVT".into()
    });
    Ok(MaintenanceReport {
        version: release.version,
        changed: true,
        binaries_updated: binaries,
        steps,
    })
}

/// «Переустановить»: комплект из поставки KVT (или заново скачанный по зафиксированному
/// хэшу, если он повреждён), чистые списки и драйвер WinDivert, который поставится заново.
/// `touch_driver` — нет чужих программ, которые сейчас пользуются WinDivert.
pub async fn repair(paths: &Paths, touch_driver: bool) -> Result<MaintenanceReport, String> {
    let mut steps = Vec::new();
    if paths.zapret_update.exists() {
        std::fs::remove_dir_all(&paths.zapret_update).map_err(|e| e.to_string())?;
        steps.push("Обновление удалено — используется комплект из KVT".to_owned());
    }
    if paths.zapret_lists.exists() {
        let _ = std::fs::remove_dir_all(&paths.zapret_lists);
        steps.push("Рабочие списки сброшены — создадутся при запуске".to_owned());
    }
    let mut version = read_version(&paths.zapret);
    match check_bundle(&paths.zapret) {
        Ok(_) => steps.push(format!("Файлы комплекта целы (Flowseal {version})")),
        Err(problem) => {
            steps.push(format!("Комплект повреждён: {problem}"));
            version = zapret::FLOWSEAL_VERSION.to_owned();
            download_bundle(
                paths,
                &zapret::archive_url(&version),
                zapret::ARCHIVE_SHA256,
                &version,
                &paths.zapret.join("bin"),
            )
            .await?;
            steps.push(format!(
                "Комплект Flowseal {version} скачан заново и проверен"
            ));
        }
    }
    if touch_driver {
        match remove_driver() {
            Ok(()) => {
                steps.push("Драйвер WinDivert удалён — установится заново при запуске".to_owned())
            }
            Err(e) => steps.push(format!("Драйвер WinDivert не удалось переустановить: {e}")),
        }
    } else {
        steps.push("Драйвер WinDivert не тронут: им пользуется другая программа".to_owned());
    }
    Ok(MaintenanceReport {
        version,
        changed: true,
        binaries_updated: false,
        steps,
    })
}

/// Списки Flowseal копируются в защищённый каталог, рядом — свои `*-user.txt`.
fn prepare_lists(
    paths: &Paths,
    bundle: &Path,
    lists: &zapret::UserLists,
    ipset: bool,
) -> Result<(), String> {
    secure_dir(&paths.zapret_lists)?;
    let source = bundle.join("lists");
    copy_files(
        &source,
        &paths.zapret_lists,
        |n| n.ends_with(".txt") && !n.ends_with("-user.txt"),
        MAX_LIST,
    )?;
    if ipset {
        // Режим Flowseal «loaded»: полный IP-список вместо заглушки.
        std::fs::copy(
            source.join("ipset-all.txt.backup"),
            paths.zapret_lists.join("ipset-all.txt"),
        )
        .map_err(|_| "в комплекте нет полного IP-списка (ipset-all.txt.backup)".to_string())?;
    }
    for (name, text) in [
        ("list-general-user.txt", &lists.general),
        ("list-exclude-user.txt", &lists.exclude),
        ("ipset-exclude-user.txt", &lists.ipset_exclude),
    ] {
        std::fs::write(paths.zapret_lists.join(name), text)
            .map_err(|e| format!("список {name}: {e}"))?;
    }
    Ok(())
}

/// То же, что делает Flowseal при каждом запуске; у нас — только с разрешения.
fn enable_tcp_timestamps() {
    let _ = std::process::Command::new("netsh")
        .args(["interface", "tcp", "set", "global", "timestamps=enabled"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

/// Адреса VPN-серверов: IP как есть, домены — как домены и их текущие IP.
async fn server_addresses(servers: &[String]) -> (Vec<String>, Vec<IpAddr>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    for s in servers {
        if let Ok(ip) = s.parse::<IpAddr>() {
            ips.push(ip);
            continue;
        }
        let host = s.to_ascii_lowercase();
        if zapret::valid_domain(&host) {
            if let Ok(Ok(found)) = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), 443)),
            )
            .await
            {
                ips.extend(found.map(|a| a.ip()));
            }
            domains.push(host);
        }
    }
    ips.sort();
    ips.dedup();
    (domains, ips)
}

fn with_separator(dir: &Path) -> String {
    let mut s = dir.to_string_lossy().into_owned();
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

/// Запускает winws. `servers` — адреса VPN-серверов (в гибриде), `interface` —
/// физический интерфейс, если рядом работает TUN.
pub async fn start(
    paths: &Paths,
    plan: &ZapretPlan,
    domains: &[String],
    servers: &[String],
    interface: Option<u32>,
    log: &Log,
) -> Result<Winws, String> {
    if !zapret::valid_id(&plan.strategy) {
        return Err(format!("неизвестная стратегия «{}»", plan.strategy));
    }
    let bundle = active_bundle(paths);
    let strategy = scan_strategies(&bundle)
        .0
        .into_iter()
        .find(|s| s.id == plan.strategy)
        .ok_or_else(|| format!("стратегии «{}» нет в комплекте zapret", plan.strategy))?;
    let bin = bundle.join("bin");
    verify_binaries(&bin).map_err(|e| {
        format!("Файлы zapret повреждены ({e}). Нажмите «Переустановить» во вкладке Zapret или запустите scripts\\fetch-zapret.ps1")
    })?;

    let (server_domains, server_ips) = server_addresses(servers).await;
    let lists = zapret::user_lists(domains, &plan.exclude_domains, &server_domains, &server_ips)
        .map_err(|e| e.to_string())?;
    prepare_lists(paths, &bundle, &lists, plan.ipset)?;
    if strategy.needs_timestamps && plan.tcp_timestamps {
        enable_tcp_timestamps();
    }

    let args = zapret::render(
        &strategy,
        &RenderContext {
            bin: &with_separator(&bin),
            lists: &with_separator(&paths.zapret_lists),
            game: plan.game_filter,
            interface,
        },
    );
    let mut cmd = Command::new(bin.join("winws.exe"));
    cmd.args(&args).current_dir(&bin);
    let (child, job) = spawn_supervised(cmd, log, "zapret").await?;
    tracing::info!(strategy = %strategy.id, ?interface, "zapret запущен");
    Ok(Winws {
        child,
        _job: job,
        strategy: strategy.id,
    })
}

fn service_running(name: &str) -> bool {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return false;
    };
    manager
        .open_service(name, ServiceAccess::QUERY_STATUS)
        .and_then(|s| s.query_status())
        .is_ok_and(|st| st.current_state != ServiceState::Stopped)
}

/// PID процессов по имени образа (`tasklist`, независимо от языка Windows).
fn pids(image: &str) -> Vec<u32> {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {image}"), "/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    out.lines()
        .filter_map(|line| {
            let mut fields = line.split("\",\"").map(|f| f.trim_matches('"'));
            let name = fields.next()?;
            let pid = fields.next()?.parse().ok()?;
            name.eq_ignore_ascii_case(image).then_some(pid)
        })
        .collect()
}

/// Чужие обходы: службы и процессы winws/GoodbyeDPI не из комплектов KVT.
pub fn conflicts(paths: &Paths, own_pid: Option<u32>) -> Vec<(Conflict, Option<u32>)> {
    let mut out: Vec<(Conflict, Option<u32>)> = CONFLICTING_SERVICES
        .iter()
        .filter(|name| service_running(name))
        .map(|name| {
            (
                Conflict {
                    service: true,
                    name: (*name).to_owned(),
                },
                None,
            )
        })
        .collect();
    let ours = [
        paths.zapret.join("bin").join("winws.exe"),
        paths.zapret_update.join("bin").join("winws.exe"),
    ];
    for image in CONFLICTING_PROCESSES {
        for pid in pids(image) {
            if Some(pid) == own_pid {
                continue;
            }
            let path = crate::win::process_image(pid).ok();
            if path
                .as_deref()
                .is_some_and(|p| ours.iter().any(|o| same_file(p, o)))
            {
                continue;
            }
            out.push((
                Conflict {
                    service: false,
                    name: path
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| (*image).to_owned()),
                },
                Some(pid),
            ));
        }
    }
    out
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
    }
}

/// Останавливает найденное (службы — остановкой, процессы — завершением). Ничего не удаляет.
pub fn stop_conflicts(paths: &Paths, own_pid: Option<u32>) -> Vec<Conflict> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok();
    for (conflict, pid) in conflicts(paths, own_pid) {
        match pid {
            None => {
                if let Some(service) = manager
                    .as_ref()
                    .and_then(|m| m.open_service(&conflict.name, ServiceAccess::STOP).ok())
                {
                    let _ = service.stop();
                }
            }
            Some(pid) => {
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
            }
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    conflicts(paths, own_pid)
        .into_iter()
        .map(|(c, _)| c)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_bundle() -> Option<PathBuf> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/zapret");
        root.exists().then_some(root)
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kvt-zapret-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn separator_is_added_once() {
        assert_eq!(with_separator(Path::new(r"C:\KVT\bin")), r"C:\KVT\bin\");
        assert_eq!(with_separator(Path::new(r"C:\KVT\bin\")), r"C:\KVT\bin\");
    }

    #[tokio::test]
    async fn server_ips_and_domains_are_split() {
        let (domains, ips) = server_addresses(&[
            "203.0.113.10".into(),
            "bad name;".into(),
            "localhost".into(),
        ])
        .await;
        assert_eq!(domains, ["localhost"]);
        assert!(ips.contains(&"203.0.113.10".parse().unwrap()));
    }

    /// Комплект для разработки (`scripts/fetch-zapret.ps1`): все стратегии и хэши.
    #[test]
    fn dev_bundle_is_valid() {
        let Some(root) = dev_bundle() else {
            eprintln!("нет комплекта zapret, пропуск");
            return;
        };
        let (ok, rejected) = check_bundle(&root).unwrap();
        assert_eq!(ok.len(), zapret::PREFERRED_ORDER.len());
        assert!(rejected.is_empty());
        assert_eq!(read_version(&root), zapret::FLOWSEAL_VERSION);
    }

    /// Релиз с подменённым winws.exe и опасной стратегией: в комплект попадают только
    /// проверенные программы и стратегии из белого списка.
    #[test]
    fn staging_keeps_known_binaries_and_safe_strategies() {
        let Some(root) = dev_bundle() else {
            return;
        };
        let release = tmp("release");
        for sub in ["bin", "lists"] {
            std::fs::create_dir_all(release.join(sub)).unwrap();
        }
        copy_files(&root.join("bin"), &release.join("bin"), |_| true, u64::MAX).unwrap();
        copy_files(
            &root.join("lists"),
            &release.join("lists"),
            |_| true,
            u64::MAX,
        )
        .unwrap();
        std::fs::write(release.join("bin").join("winws.exe"), b"not the real winws").unwrap();
        std::fs::copy(
            root.join("strategies").join("general.bat"),
            release.join("general.bat"),
        )
        .unwrap();
        std::fs::write(
            release.join("general (EVIL).bat"),
            "start \"z\" /min \"%BIN%winws.exe\" --debug=@C:\\Windows\\evil.dll\n",
        )
        .unwrap();

        let staging = tmp("staging");
        let binaries_new = stage(&release, &root.join("bin"), &staging, "9.9.9").unwrap();
        assert!(!binaries_new, "подменённый winws.exe не должен приниматься");
        verify_binaries(&staging.join("bin")).unwrap();
        let (ok, _) = check_bundle(&staging).unwrap();
        assert_eq!(ok.len(), 1);
        assert!(!staging
            .join("strategies")
            .join("general (EVIL).bat")
            .exists());
        assert_eq!(read_version(&staging), "9.9.9");
        let _ = std::fs::remove_dir_all(&release);
        let _ = std::fs::remove_dir_all(&staging);
    }

    /// Системный tar.exe распаковывает zip с каталогом верхнего уровня, как у Flowseal.
    #[test]
    fn extract_unpacks_zip() {
        let src = tmp("zip-src");
        let inner = src.join("zapret-discord-youtube-9.9.9");
        std::fs::create_dir_all(inner.join("lists")).unwrap();
        std::fs::write(
            inner.join("lists").join("list-general.txt"),
            "discord.com\n",
        )
        .unwrap();
        let archive = tmp("zip").join("r.zip");
        let system = std::env::var_os("SystemRoot")
            .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        let ok = std::process::Command::new(system.join("System32").join("tar.exe"))
            .arg("-a")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&src)
            .arg("zapret-discord-youtube-9.9.9")
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let dest = tmp("zip-out");
        let root = extract(&archive, &dest).unwrap();
        assert!(root.ends_with("zapret-discord-youtube-9.9.9"));
        assert_eq!(
            std::fs::read_to_string(root.join("lists").join("list-general.txt")).unwrap(),
            "discord.com\n"
        );
        for d in [src, dest, archive.parent().unwrap().to_path_buf()] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn broken_bundle_is_reported() {
        let empty = tmp("empty");
        assert!(check_bundle(&empty).is_err());
        assert_eq!(read_version(&empty), "неизвестна");
        let _ = std::fs::remove_dir_all(&empty);
    }
}
