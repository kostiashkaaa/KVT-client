//! Запуск и остановка ядра. Конфиг строится службой из проверенного плана,
//! проверяется самим ядром, живёт на диске только до старта ядра (в каталоге,
//! доступном лишь SYSTEM и администраторам), а процесс ядра помещается в
//! Job Object и не переживает службу.

use crate::dirs::secure_dir;
pub use crate::dirs::Paths;
use crate::net::NetClient;
use crate::wfp::{self, DnsGuard, KillSwitch};
use crate::win::Job;
use kvt_core::compile::{compile, CompileInput, TUN_INTERFACE};
use kvt_core::core_errors::{self, Triggered};
use kvt_core::core_select::CoreKind;
use kvt_core::ipc::{ConnectPlan, ZapretPlan};
use kvt_core::rulesync;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};

mod adapter;
mod checked;
mod killswitch;
mod process;

use adapter::*;
use checked::*;
use killswitch::*;
pub use process::spawn_supervised;
use process::*;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Сколько ждём после запуска, чтобы поймать мгновенное падение ядра. VPN-ядро
/// отпускается раньше — как только маршрут в интернет пошёл через его TUN.
const STARTUP_GRACE: Duration = Duration::from_secs(2);
/// Как часто во время `STARTUP_GRACE` смотрим, не готов ли процесс.
const READY_POLL: Duration = Duration::from_millis(50);
const LOG_LINES: usize = 200;
/// Сколько байт строки вывода ядра хранить (см. `clip`).
const MAX_LINE: usize = 1024;
/// Адрес, по маршруту к которому видно, куда сейчас идёт интернет: в старый TUN,
/// в новый или в физический адаптер.
const ROUTE_PROBE: std::net::Ipv4Addr = std::net::Ipv4Addr::new(8, 8, 8, 8);
pub type Log = Arc<Mutex<VecDeque<String>>>;

fn recent(log: &Log, n: usize) -> Vec<String> {
    let log = log.lock().map(|l| l.clone()).unwrap_or_default();
    log.iter().rev().take(n).rev().cloned().collect()
}

/// То, что нужно командам без состояния подключения (журналы, сведения о zapret,
/// конфликты): служба отвечает на них, не дожидаясь блокировки, которую держит
/// подключение или установка обновления.
#[derive(Clone)]
pub struct Shared {
    paths: Paths,
    log: Log,
    zapret_pid: Arc<AtomicU32>,
}

impl Shared {
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn recent_log(&self, n: usize) -> Vec<String> {
        recent(&self.log, n)
    }

    pub fn zapret_pid(&self) -> Option<u32> {
        Some(self.zapret_pid.load(Ordering::Relaxed)).filter(|&pid| pid != 0)
    }

    /// Стереть отметку kill switch, не дожидаясь блокировки состояния: служба
    /// останавливается штатно, и после запуска закрывать интернет не нужно.
    pub fn forget_kill_switch(&self) {
        clear_marker(&self.paths.run.join(KILL_SWITCH_MARKER));
    }
}

/// Сработавшее правило ошибок ядра, которое ещё не обработано.
pub type Issues = Arc<Mutex<Option<Triggered>>>;

struct Running {
    child: Child,
    _job: Job,
    /// DNS мимо туннеля закрыт, пока работает ядро (`wfp::DnsGuard`).
    dns_guard: Option<DnsGuard>,
}

/// Файл, который удаляется при выходе из области видимости — в том числе когда
/// запуск брошен на `.await` (отмена подключения).
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub struct Supervisor {
    paths: Paths,
    running: Option<Running>,
    /// Живёт отдельно от процесса ядра: если ядро упало, блокировка остаётся
    /// до явного «Отключить».
    kill_switch: Option<KillSwitch>,
    /// winws: в гибриде рядом с ядром, в режиме zapret — один. Менять только через
    /// `set_zapret`: его pid читают команды без блокировки (`Shared`).
    zapret: Option<crate::zapret::Winws>,
    zapret_pid: Arc<AtomicU32>,
    log: Log,
    issues: Issues,
    /// Последний план подключения — для переподключения по ошибке ядра.
    last_plan: Option<ConnectPlan>,
    /// По ошибке ядра уже переподключались (делается один раз на подключение).
    reconnected: bool,
    /// Конфиги, которые ядро уже приняло: повторно не проверяются.
    checked: CheckedConfigs,
    /// Ядро не смогло настроить IPv6 у адаптера: до перезапуска службы TUN
    /// собирается только с IPv4, чтобы следующие подключения не ждали 15 попыток.
    ipv6_failed: bool,
    /// Ядро завершилось с ошибкой, после которой положено переподключиться:
    /// `exited` положил её в `issues`, `handle_issue` переподключит.
    retry_after_exit: bool,
    /// До какого момента открыт выход тестовому ядру (`open_probe`): окно могло
    /// закрыться, не сказав `ProbeClose`.
    probe_until: Option<Instant>,
}

/// Код правила из `presets/core-errors.json`: ядро не может задать адаптеру IPv6.
const TUN_IPV6: &str = "tun_ipv6";

impl Supervisor {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            running: None,
            kill_switch: None,
            zapret: None,
            zapret_pid: Arc::default(),
            log: Log::default(),
            issues: Issues::default(),
            last_plan: None,
            reconnected: false,
            ipv6_failed: false,
            checked: CheckedConfigs::default(),
            retry_after_exit: false,
            probe_until: None,
        }
    }

    pub fn recent_log(&self, n: usize) -> Vec<String> {
        recent(&self.log, n)
    }

    /// Для команд без блокировки состояния (см. `Shared`).
    pub fn shared(&self) -> Shared {
        Shared {
            paths: self.paths.clone(),
            log: Arc::clone(&self.log),
            zapret_pid: Arc::clone(&self.zapret_pid),
        }
    }

    fn set_zapret(&mut self, winws: Option<crate::zapret::Winws>) {
        let pid = winws.as_ref().and_then(crate::zapret::Winws::pid);
        self.zapret_pid.store(pid.unwrap_or(0), Ordering::Relaxed);
        self.zapret = winws;
    }

    /// Запуск или переподключение. При смене сервера с kill switch прежние фильтры
    /// держатся, пока не встанут новые: интернет на это время закрыт, но мимо
    /// туннеля не уходит ни одного пакета. Подуровни WFP у сессий разные, поэтому
    /// два набора фильтров не конфликтуют.
    pub async fn start(&mut self, plan: &ConnectPlan) -> Result<(), String> {
        self.reconnected = false;
        self.connect(plan).await
    }

    async fn connect(&mut self, plan: &ConnectPlan) -> Result<(), String> {
        self.last_plan = Some(plan.clone());
        let previous = if plan.kill_switch {
            self.kill_switch.take()
        } else {
            None
        };
        let result = self.start_inner(plan).await;
        if result.is_err() {
            // Ядро не поднялось — zapret без него в гибриде не нужен.
            self.set_zapret(None);
        }
        if let (Err(e), Some(previous)) = (&result, previous) {
            if self.kill_switch.is_none() {
                // Защиту включали до переподключения — не снимаем её из-за сбоя.
                self.kill_switch = Some(previous);
                self.mark_kill_switch(true);
                return Err(kvt_core::trf!(
                    "{e}. Kill switch держит интернет закрытым — нажмите «Отключить» или подключитесь заново",
                    "{e}. The kill switch is keeping the internet blocked — press “Disconnect” or connect again"
                ));
            }
        }
        result
    }

    async fn start_inner(&mut self, plan: &ConnectPlan) -> Result<(), String> {
        // Адреса имён сервера — через DoH, не DNS провайдера: их получают ядро (само
        // имя не резолвит), маскировщик журналов и (в гибриде) исключения winws.
        hide_server_addresses(&plan.server);
        let endpoints = plan.server.endpoints();
        let hosts =
            crate::net::server_ips(&endpoints, plan.server.port, plan.dns.remote_id()).await;
        kvt_core::redact::add_servers(
            hosts
                .iter()
                .flat_map(|(_, ips)| ips.iter().map(std::net::IpAddr::to_string)),
        );
        let servers = match &plan.zapret {
            Some(_) => crate::zapret::server_addresses(&endpoints, &hosts),
            None => crate::zapret::ServerAddresses::default(),
        };
        self.stop_running().await;
        remove_stale_wintun_devices().await;
        wait_adapter_removed().await;
        plan.routing.validate().map_err(|e| e.to_string())?;
        if !crate::win::is_elevated() {
            tracing::error!("служба без прав администратора — TUN не создать");
            return Err(kvt_core::i18n::tr(
                "Службе KVT не хватает прав, чтобы создать сетевой адаптер. Переустановите KVT — служба должна работать от имени системы.",
                "The KVT service lacks the rights to create a network adapter. Reinstall KVT — the service must run as SYSTEM.",
            )
            .into());
        }
        secure_dir(&self.paths.rules)?;
        secure_dir(&self.paths.run)?;

        // Списки. Все файлы на месте — подключаемся сразу, а новые версии (раз в сутки)
        // качаем в фоне после подключения: применятся при следующем. Раньше первое
        // подключение за день ждало GitHub, а у части провайдеров он медленный.
        // Каких-то файлов нет — качаем сейчас: без них ядро не запустится.
        let files = rulesync::required_files(&plan.routing, plan.core);
        let complete = files
            .iter()
            .all(|f| self.paths.rules.join(&f.local).exists());
        let (background, force) = if complete {
            (files, false)
        } else {
            let http =
                NetClient::new(kvt_core::netlog::Purpose::Rules).map_err(|e| e.to_string())?;
            let report = rulesync::sync(&http, &self.paths.rules, &files, unix_now(), false).await;
            for (file, err) in &report.failed {
                tracing::warn!(file, err, "список не обновлён");
            }
            if !report.updated.is_empty() {
                self.checked.forget();
            }
            if let Some(missing) = files
                .iter()
                .find(|f| !self.paths.rules.join(&f.local).exists())
            {
                return Err(kvt_core::trf!(
                    "Не удалось загрузить список «{}» с GitHub. Проверьте интернет и подключитесь снова.",
                    "Couldn't download the list “{}” from GitHub. Check your internet and connect again.",
                    missing.local
                ));
            }
            // Прежние версии на месте, но обновить не вышло: повторим через туннель,
            // когда он поднимется.
            let retry: Vec<rulesync::RuleFile> = files
                .iter()
                .filter(|f| report.failed.iter().any(|(n, _)| *n == f.local))
                .cloned()
                .collect();
            (retry, true)
        };

        if let Some(zp) = &plan.zapret {
            // winws — до ядра, пока трафик ещё идёт через физический интерфейс.
            let interface = physical_interface().await;
            let winws = crate::zapret::start(
                &self.paths,
                zp,
                &plan.routing.zapret_hostlist(),
                // И сервер загрузки XHTTP: winws не должен трогать соединения ядра.
                &servers,
                interface,
                &self.log,
            )
            .await?;
            self.set_zapret(Some(winws));
        }

        let rules = self.paths.rules.to_string_lossy().replace('\\', "/");
        let disabled = crate::win::ipv6_disabled_components();
        let ipv6 = kvt_core::compile::ipv6_enabled(disabled) && !self.ipv6_failed;
        if !ipv6 {
            tracing::info!(
                disabled_components = ?disabled,
                failed = self.ipv6_failed,
                "IPv6 у адаптера недоступен: TUN только с IPv4"
            );
        }
        let compiled = compile(
            plan.core,
            &CompileInput {
                server: &plan.server,
                routing: &plan.routing,
                dns: &plan.dns,
                rule_set_dir: &rules,
                ipv6,
                hosts: &hosts,
            },
        )
        .map_err(|e| e.to_string())?;
        let config = serde_json::to_vec(&compiled.config).map_err(|e| e.to_string())?;
        let fingerprint = config_fingerprint(plan.core, &config);

        let spec = CoreSpec::new(plan.core, &self.paths);
        let config_path = self.paths.run.join(spec.config_name);
        // Секреты на диске не задерживаются: файл удаляется, как только ядро его
        // прочитало (или не запустилось), — и когда запуск отменён на полпути.
        let config_file = RemoveOnDrop(config_path);
        std::fs::write(&config_file.0, config).map_err(|e| {
            kvt_core::trf!(
                "не удалось записать конфиг: {e}",
                "couldn't write the config: {e}"
            )
        })?;
        if let Ok(mut issues) = self.issues.lock() {
            *issues = None;
        }
        let result = self
            .check_and_spawn(&spec, &config_file.0, fingerprint)
            .await;
        drop(config_file);
        let (child, job) = result?;
        self.running = Some(Running {
            child,
            _job: job,
            dns_guard: None,
        });

        // Ядро уже проверило, что интернет пошёл через его TUN, — адаптер на месте.
        let luid = match self.wait_tun().await {
            Ok(luid) => luid,
            Err(e) => {
                self.stop_running().await;
                return Err(e);
            }
        };
        if let Err(e) = self.enable_dns_guard(luid, !ipv6) {
            // Как и с kill switch: не оставляем соединение, у которого DNS уходит мимо.
            self.stop_running().await;
            tracing::error!(error = %e, "DNS мимо туннеля не закрыт");
            return Err(kvt_core::trf!(
                "Не удалось закрыть DNS-запросы мимо VPN, поэтому подключение остановлено. Подключитесь снова; если повторится — сохраните диагностику. ({e})",
                "Couldn't block DNS requests outside the VPN, so the connection was stopped. Connect again; if it happens again, save diagnostics. ({e})"
            ));
        }
        if plan.kill_switch {
            if let Err(e) = self.enable_kill_switch(luid) {
                // Защиту обещали, но включить не смогли — не оставляем «полузащищённое» соединение.
                self.stop_running().await;
                tracing::error!(error = %e, "kill switch не включился");
                return Err(kvt_core::trf!(
                    "Не удалось включить kill switch, поэтому подключение остановлено. Подключитесь снова; если повторится — выключите kill switch в настройках и сохраните диагностику. ({e})",
                    "Couldn't turn on the kill switch, so the connection was stopped. Connect again; if it happens again, turn off the kill switch in settings and save diagnostics. ({e})"
                ));
            }
        }
        tracing::info!(core = ?plan.core, kill_switch = plan.kill_switch, "подключено");
        if !background.is_empty() {
            spawn_rules_sync(
                self.paths.rules.clone(),
                background,
                force,
                self.checked.clone(),
            );
        }
        Ok(())
    }

    /// Сработало правило ошибок ядра, после которого положено переподключиться.
    /// Переподключение идёт секунды, поэтому `Status` его не делает: служба
    /// запускает его отдельно, и «Отключить» его прерывает (`pipe::reconnect`).
    pub fn reconnect_pending(&self) -> bool {
        let Ok(issues) = self.issues.lock() else {
            return false;
        };
        let Some(issue) = issues.as_ref() else {
            return false;
        };
        if self.running.is_none() && !self.retry_after_exit {
            return false;
        }
        issue.action == core_errors::Action::Reconnect
            && ((issue.code == TUN_IPV6 && !self.ipv6_failed) || !self.reconnected)
    }

    /// Обрабатывает сработавшее правило ошибок ядра. `Some(текст)` — подключение
    /// остановлено, текст — причина для пользователя. Без `reconnect` правило, по
    /// которому надо переподключиться, остаётся ждать (`reconnect_pending`).
    pub async fn handle_issue(&mut self, reconnect: bool) -> Option<String> {
        if !reconnect && self.reconnect_pending() {
            return None;
        }
        let issue = self.issues.lock().ok()?.take()?;
        // Ядро уже не работает — действуем, только если это повтор после его выхода.
        let after_exit = std::mem::take(&mut self.retry_after_exit);
        if self.running.is_none() && !after_exit {
            return None;
        }
        match issue.action {
            core_errors::Action::Log => None,
            // Windows не дала задать адаптеру IPv6 (IPv6 выключен способом, которого не
            // видно в реестре). Без переподключения ядро сдалось бы через 15 попыток.
            // Не тратит общий повтор: следующий старт может упереться в «адаптер занят».
            core_errors::Action::Reconnect if issue.code == TUN_IPV6 && !self.ipv6_failed => {
                self.ipv6_failed = true;
                let plan = self.last_plan.clone()?;
                tracing::warn!(
                    "Windows не дала настроить IPv6 у адаптера — переподключение только с IPv4"
                );
                match self.connect(&plan).await {
                    Ok(()) => None,
                    Err(e) => Some(format!("{} {e}", issue.text)),
                }
            }
            core_errors::Action::Reconnect if !self.reconnected => {
                self.reconnected = true;
                let plan = self.last_plan.clone()?;
                tracing::warn!(code = %issue.code, "переподключение по ошибке ядра");
                match self.connect(&plan).await {
                    Ok(()) => None,
                    Err(e) => Some(format!("{} {e}", issue.text)),
                }
            }
            core_errors::Action::Reconnect | core_errors::Action::Stop => {
                tracing::warn!(code = %issue.code, "подключение остановлено по ошибке ядра");
                self.halt_core().await;
                Some(kvt_core::trf!(
                    "{} Подключение остановлено.",
                    "{} Connection stopped.",
                    issue.text
                ))
            }
        }
    }

    /// Останавливает ядро и zapret, но не kill switch: как при падении ядра,
    /// интернет мимо туннеля не открывается до явного «Отключить».
    async fn halt_core(&mut self) {
        if let Some(mut running) = self.running.take() {
            let _ = running.child.kill().await;
        }
        self.set_zapret(None);
    }

    /// VPN-ядро сейчас работает.
    pub fn vpn_running(&self) -> bool {
        self.running.is_some()
    }

    /// Ждёт интерфейс TUN. Он появляется не мгновенно после старта ядра: Wintun сам
    /// ждёт устройство до 15 с. Ждём дольше, но не дольше, чем живёт ядро.
    async fn wait_tun(&mut self) -> Result<u64, String> {
        for _ in 0..200 {
            if let Some(luid) = wfp::interface_luid(TUN_INTERFACE) {
                return Ok(luid);
            }
            let exited = self
                .running
                .as_mut()
                .is_none_or(|r| matches!(r.child.try_wait(), Ok(Some(_))));
            if exited {
                let last = self.recent_log(1).pop().unwrap_or_default();
                return Err(kvt_core::trf!(
                    "VPN-ядро остановилось, не создав адаптер: {last}",
                    "The VPN core stopped without creating an adapter: {last}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(kvt_core::i18n::tr(
            "интерфейс TUN не появился за 20 с",
            "the TUN interface didn't appear within 20 s",
        )
        .into())
    }

    async fn check_and_spawn(
        &self,
        spec: &CoreSpec,
        config: &Path,
        fingerprint: u64,
    ) -> Result<(Child, Job), String> {
        let start = std::time::Instant::now();
        if !self.checked.contains(fingerprint) {
            let check = Command::new(&spec.exe)
                .args(spec.check_args(config))
                .envs(spec.env.clone())
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .await
                .map_err(|e| {
                    kvt_core::trf!(
                        "не удалось запустить {}: {e}",
                        "couldn't start {}: {e}",
                        spec.exe.display()
                    )
                })?;
            if !check.status.success() {
                let text =
                    String::from_utf8_lossy(&[check.stdout, check.stderr].concat()).into_owned();
                let detail = tail(&kvt_core::redact::text(&text), 3);
                tracing::error!(%detail, "ядро отвергло конфигурацию");
                return Err(kvt_core::trf!(
                    "VPN-ядро не приняло настройки этого сервера — возможно, в ключе неподдерживаемые параметры. Выберите другой сервер или сохраните диагностику. ({detail})",
                    "The VPN core rejected this server's settings — the key may have unsupported parameters. Pick another server or save diagnostics. ({detail})"
                ));
            }
            self.checked.remember(fingerprint);
        }
        let checked = start.elapsed();
        let mut cmd = Command::new(&spec.exe);
        cmd.args(spec.run_args(config))
            .envs(spec.env.clone())
            .current_dir(&self.paths.run);
        // Готово, когда интернет пошёл через новый TUN. Если адаптер остался от
        // прежнего ядра (уборка не удалась), по маршруту этого не понять — тогда
        // ждём весь `STARTUP_GRACE`, как раньше.
        let fresh = wfp::interface_luid(TUN_INTERFACE).is_none();
        let spawned = spawn_supervised(
            cmd,
            &self.log,
            kvt_core::i18n::tr("ядро", "core"),
            Some((spec.core, Arc::clone(&self.issues))),
            move || fresh && route_through_tun(),
        )
        .await;
        if spawned.is_ok() {
            tracing::info!(
                check_ms = checked.as_millis() as u64,
                start_ms = (start.elapsed() - checked).as_millis() as u64,
                "ядро запущено"
            );
        }
        spawned
    }

    /// Только zapret, без VPN: winws на всех интерфейсах.
    pub async fn start_zapret(&mut self, plan: &ZapretPlan) -> Result<String, String> {
        self.stop().await;
        if !crate::win::is_elevated() {
            return Err(kvt_core::i18n::tr(
                "Службе KVT не хватает прав, чтобы запустить zapret. Переустановите KVT — служба должна работать от имени системы.",
                "The KVT service lacks the rights to start zapret. Reinstall KVT — the service must run as SYSTEM.",
            )
            .into());
        }
        let winws = crate::zapret::start(
            &self.paths,
            plan,
            &plan.domains,
            &crate::zapret::ServerAddresses::default(),
            None,
            &self.log,
        )
        .await?;
        let strategy = winws.strategy.clone();
        self.set_zapret(Some(winws));
        Ok(strategy)
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn zapret_pid(&self) -> Option<u32> {
        self.zapret.as_ref().and_then(|z| z.pid())
    }

    /// Всё остановить и выключить kill switch: «Отключить», отмена, выход службы.
    /// Отметка стирается и тогда, когда kill switch уже снят: отмена переподключения
    /// бросает прежний kill switch вместе с недоделанным запуском.
    pub async fn stop(&mut self) {
        self.stop_running().await;
        self.mark_kill_switch(false);
    }

    /// Остановка внутри запуска. Прежний kill switch при переподключении держит
    /// `connect`, и его отметка остаётся.
    async fn stop_running(&mut self) {
        if let Some(mut running) = self.running.take() {
            let _ = running.child.kill().await;
            tracing::info!("ядро остановлено");
        }
        if self.zapret.is_some() {
            self.set_zapret(None);
            tracing::info!("zapret остановлен");
        }
        if self.kill_switch.take().is_some() {
            self.mark_kill_switch(false);
            tracing::info!("kill switch выключен");
        }
        // Правило ошибок прежнего ядра не должно переподключить то, что остановлено.
        if let Ok(mut issues) = self.issues.lock() {
            *issues = None;
        }
        self.retry_after_exit = false;
    }

    /// Если ядро или zapret завершились сами — причина (последние строки лога).
    pub fn exited(&mut self) -> Option<String> {
        if let Some(reason) = self.zapret.as_mut().and_then(crate::zapret::Winws::exited) {
            self.set_zapret(None);
            let last = self.recent_log(1).pop().unwrap_or_default();
            tracing::error!(%reason, %last, "zapret завершился");
            // «Гибрид»: без winws ядро осталось бы работать, а статус — «ошибка»:
            // окно предлагало бы «Подключить», автопереключение перестало бы следить
            // за туннелем. Останавливаем и ядро — состояние совпадает со статусом,
            // kill switch (если включён) держит интернет закрытым, как при сбое ядра.
            if let Some(mut running) = self.running.take() {
                let _ = running.child.start_kill();
                tracing::info!("ядро остановлено вслед за zapret");
            }
            return Some(format!("{reason}: {last}"));
        }
        let running = self.running.as_mut()?;
        match running.child.try_wait() {
            Ok(Some(status)) => {
                self.running = None;
                let last = self.recent_log(1).pop().unwrap_or_default();
                tracing::error!(%status, %last, "ядро завершилось само");
                // «Гибрид»: без ядра winws продолжал бы менять трафик, а статус —
                // «ошибка». Переподключение запустит его заново вместе с ядром.
                if self.zapret.is_some() {
                    self.set_zapret(None);
                    tracing::info!("zapret остановлен вслед за ядром");
                }
                // Понятный текст, если последняя строка подходит под правило.
                let rule = self
                    .last_plan
                    .as_ref()
                    .and_then(|p| core_errors::classify(p.core, &last))
                    .filter(|r| r.action != core_errors::Action::Log);
                // Ошибка, после которой положено переподключиться, а ядро завершилось
                // раньше, чем её обработали (Wintun: «адаптер занят» — после остановки
                // ядра от адаптера остаётся устройство, которое Wintun убирает при
                // неудачной попытке, и следующая проходит). Переподключает handle_issue.
                if let Some(rule) =
                    rule.filter(|r| r.action == core_errors::Action::Reconnect && !self.reconnected)
                {
                    if let Ok(mut slot) = self.issues.lock() {
                        *slot = Some(core_errors::Triggered {
                            code: rule.code.clone(),
                            text: rule.message().to_owned(),
                            action: rule.action,
                        });
                        self.retry_after_exit = true;
                        return None;
                    }
                }
                let known = rule.map(|r| r.message().to_owned());
                Some(known.unwrap_or_else(|| {
                    kvt_core::trf!(
                        "VPN-ядро неожиданно остановилось: {last}",
                        "The VPN core stopped unexpectedly: {last}"
                    )
                }))
            }
            _ => None,
        }
    }
}

/// Адрес сервера — маскировщику журналов до запуска ядра: в строках ядра его не
/// придётся угадывать. Сервер загрузки XHTTP (`downloadSettings`) скрывается так же;
/// IP имён добавляются, когда их найдёт `net::server_ips`, а прежние — сразу.
///
/// Адреса только добавляются: прежнее ядро ещё допишет строки о прежнем сервере.
fn hide_server_addresses(server: &kvt_core::Server) {
    let endpoints = server.endpoints();
    kvt_core::redact::add_servers(&endpoints);
    kvt_core::redact::set_secrets(server.secrets());
    for host in &endpoints {
        kvt_core::redact::add_servers(
            crate::net::known_ips(host)
                .iter()
                .map(std::net::IpAddr::to_string),
        );
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Обновление списков после подключения: сначала напрямую мимо TUN, при неудаче —
/// через туннель. Ядро уже работает на прежних версиях; новые применятся при
/// следующем подключении. `force` — повтор того, что не скачалось перед
/// подключением; иначе качается только то, чему подошёл срок (раз в сутки).
fn spawn_rules_sync(
    dir: PathBuf,
    files: Vec<rulesync::RuleFile>,
    force: bool,
    checked: CheckedConfigs,
) {
    tokio::spawn(async move {
        // Даём TUN и маршрутам подняться.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Ok(http) = NetClient::new(kvt_core::netlog::Purpose::Rules) else {
            return;
        };
        let http = http.with_tunnel_fallback();
        let report = rulesync::sync(&http, &dir, &files, unix_now(), force).await;
        for (file, err) in &report.failed {
            tracing::warn!(file, err, "список не обновился после подключения");
        }
        for file in &report.updated {
            tracing::info!(file, "список обновлён после подключения");
        }
        if !report.updated.is_empty() {
            checked.forget();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supervisor() -> Supervisor {
        let tmp = std::env::temp_dir().join("kvt-supervisor-test");
        Supervisor::new(Paths {
            cores: tmp.clone(),
            rules: tmp.clone(),
            run: tmp.clone(),
            zapret: tmp.clone(),
            zapret_lists: tmp.clone(),
            zapret_update: tmp,
        })
    }

    /// Ядро завершилось с ошибкой, после которой положено переподключиться:
    /// `Status` переподключение не делает и правило не съедает — его делает
    /// отдельная задача, а «Отключить» стирает правило, и переподключаться нечего.
    #[tokio::test]
    async fn reconnect_waits_for_its_task_and_disconnect_drops_it() {
        let mut sup = supervisor();
        *sup.issues.lock().unwrap() = Some(Triggered {
            code: "wintun_busy".into(),
            text: "адаптер занят".into(),
            action: core_errors::Action::Reconnect,
        });
        sup.retry_after_exit = true;
        assert!(sup.reconnect_pending());
        assert_eq!(sup.handle_issue(false).await, None);
        assert!(
            sup.reconnect_pending(),
            "правило должно дождаться переподключения"
        );

        sup.stop().await;
        assert!(!sup.reconnect_pending());
        assert_eq!(sup.handle_issue(true).await, None);
    }

    /// pid winws для команд без блокировки: нет winws — нет pid.
    #[test]
    fn shared_has_no_zapret_pid_without_winws() {
        let sup = supervisor();
        assert_eq!(sup.shared().zapret_pid(), None);
        assert!(sup.shared().recent_log(10).is_empty());
    }
}
