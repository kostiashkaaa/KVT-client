//! Запуск winws: списки и подстановки, TCP timestamps, адреса VPN-серверов и сам процесс
//! (`Winws`).

use crate::dirs::{secure_dir, Paths};

use super::bundle::{active_bundle, scan_strategies, verify_binaries};
use super::stage::copy_files;
use super::ZapretError;
use super::{CREATE_NO_WINDOW, MAX_LIST};
use crate::supervisor::{spawn_supervised, Log};
use crate::win::Job;
use kvt_core::ipc::ZapretPlan;
use kvt_core::zapret::{self, RenderContext};
use std::net::IpAddr;
use std::os::windows::process::CommandExt as _;
use std::path::Path;
use std::process::Stdio;
use tokio::process::{Child, Command};

pub struct Winws {
    child: Child,
    _job: Job,
    pub strategy: String,
}

impl Winws {
    pub fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(kvt_core::trf!(
                "zapret остановился ({status})",
                "zapret stopped ({status})"
            )),
            _ => None,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
}

/// Списки Flowseal копируются в защищённый каталог, рядом — свои `*-user.txt`.
fn prepare_lists(
    paths: &Paths,
    bundle: &Path,
    lists: &zapret::UserLists,
    ipset: bool,
) -> Result<(), ZapretError> {
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
        .map_err(|_| ZapretError::NoFullIpset)?;
    }
    for (name, text) in [
        ("list-general-user.txt", &lists.general),
        ("list-exclude-user.txt", &lists.exclude),
        ("ipset-exclude-user.txt", &lists.ipset_exclude),
    ] {
        std::fs::write(paths.zapret_lists.join(name), text)
            .map_err(|e| ZapretError::List(name.to_owned(), e.to_string()))?;
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

/// Адреса VPN-серверов, которые winws не трогает (в гибриде).
#[derive(Debug, Default)]
pub struct ServerAddresses {
    pub domains: Vec<String>,
    pub ips: Vec<IpAddr>,
}

/// Адреса VPN-серверов: IP как есть, домены — как домены и их адреса, которые служба
/// уже нашла (`net::server_ips`).
pub fn server_addresses(servers: &[String], resolved: &[(String, Vec<IpAddr>)]) -> ServerAddresses {
    let mut out = ServerAddresses::default();
    for s in servers {
        if let Ok(ip) = s.parse::<IpAddr>() {
            out.ips.push(ip);
            continue;
        }
        let host = s.to_ascii_lowercase();
        if zapret::valid_domain(&host) {
            out.domains.push(host);
        }
    }
    out.ips
        .extend(resolved.iter().flat_map(|(_, ips)| ips.iter().copied()));
    out.ips.sort();
    out.ips.dedup();
    out
}

pub(super) fn with_separator(dir: &Path) -> String {
    let mut s = dir.to_string_lossy().into_owned();
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

/// Запускает winws. `servers` — адреса VPN-серверов (в гибриде, см.
/// [`server_addresses`]), `interface` — физический интерфейс, если рядом работает TUN.
pub async fn start(
    paths: &Paths,
    plan: &ZapretPlan,
    domains: &[String],
    servers: &ServerAddresses,
    interface: Option<u32>,
    log: &Log,
) -> Result<Winws, ZapretError> {
    if !zapret::valid_id(&plan.strategy) {
        return Err(ZapretError::UnknownStrategy(plan.strategy.clone()));
    }
    let bundle = active_bundle(paths);
    let strategy = scan_strategies(&bundle)
        .0
        .into_iter()
        .find(|s| s.id == plan.strategy)
        .ok_or_else(|| ZapretError::StrategyMissing(plan.strategy.clone()))?;
    let bin = bundle.join("bin");
    verify_binaries(&bin).map_err(|e| ZapretError::Damaged(Box::new(e)))?;

    let lists = zapret::user_lists(
        domains,
        &plan.exclude_domains,
        &servers.domains,
        &servers.ips,
    )?;
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
    let (child, job) = spawn_supervised(cmd, log, "zapret", None, || false).await?;
    tracing::info!(strategy = %strategy.id, ?interface, "zapret запущен");
    Ok(Winws {
        child,
        _job: job,
        strategy: strategy.id,
    })
}
