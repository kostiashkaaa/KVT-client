//! Запуск и остановка ядра. Конфиг строится службой из проверенного плана,
//! проверяется самим ядром, живёт на диске только до старта ядра (в каталоге,
//! доступном лишь SYSTEM и администраторам), а процесс ядра помещается в
//! Job Object и не переживает службу.

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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};

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
/// Сколько отпечатков принятых конфигов помнить (см. [`CHECKED`]).
const CHECKED_MAX: usize = 32;

/// Отпечатки конфигов, которые ядро уже приняло (`run -test` / `check`). Повторное
/// подключение к тому же серверу не запускает ядро лишний раз: Xray при проверке
/// читает geoip.dat на 18 МБ. Сбрасывается, когда обновились списки, — конфиг
/// ссылается на них, и новая версия может не подойти.
static CHECKED: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn config_fingerprint(core: CoreKind, config: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    format!("{core:?}").hash(&mut h);
    config.hash(&mut h);
    h.finish()
}

fn already_checked(fingerprint: u64) -> bool {
    CHECKED.lock().is_ok_and(|c| c.contains(&fingerprint))
}

fn remember_checked(fingerprint: u64) {
    if let Ok(mut c) = CHECKED.lock() {
        if c.len() >= CHECKED_MAX {
            c.remove(0);
        }
        c.push(fingerprint);
    }
}

fn forget_checked() {
    if let Ok(mut c) = CHECKED.lock() {
        c.clear();
    }
}

/// Интернет идёт через TUN KVT: адаптер есть, и маршрут к [`ROUTE_PROBE`] ведёт в него.
fn route_through_tun() -> bool {
    let tun = wfp::interface_index(TUN_INTERFACE);
    tun.is_some() && wfp::best_interface(ROUTE_PROBE) == tun
}

#[derive(Debug, Clone)]
pub struct Paths {
    /// xray.exe, sing-box.exe, wintun.dll — рядом со службой.
    pub cores: PathBuf,
    /// Списки маршрутизации.
    pub rules: PathBuf,
    /// Временные конфиги.
    pub run: PathBuf,
    /// Комплект zapret Flowseal (bin, lists, strategies) — рядом со службой.
    pub zapret: PathBuf,
    /// Рабочие списки winws, включая свои `*-user.txt`.
    pub zapret_lists: PathBuf,
    /// Комплект, обновлённый из релиза Flowseal (кнопка «Обновить»).
    pub zapret_update: PathBuf,
}

/// `C:\ProgramData\KVT`: списки, обновления zapret, журналы.
pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("KVT")
}

impl Paths {
    pub fn standard() -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let exe_dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        let data = data_dir();
        Ok(Self {
            cores: exe_dir.join("cores"),
            zapret: exe_dir.join("zapret"),
            rules: data.join("rules"),
            run: data.join("run"),
            zapret_lists: data.join("zapret"),
            zapret_update: data.join("zapret-bundle"),
        })
    }
}

/// Каталог только для SYSTEM и администраторов, владелец — администраторы
/// (`win::private_dir`). Внутри `ProgramData\KVT` сначала проверяются родители:
/// пока родитель чужой, в нём можно подложить что угодно.
pub(crate) fn secure_dir(dir: &Path) -> Result<(), String> {
    // Права ставятся раз за запуск службы: в закрытом каталоге пользователь ничего
    // не подменит, а заново — сотни миллисекунд на каждое подключение. Пропал
    // каталог или на его месте ссылка — готовим снова.
    static SECURED: Mutex<Option<std::collections::HashSet<PathBuf>>> = Mutex::new(None);
    let still_dir = std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir());
    if still_dir
        && SECURED
            .lock()
            .is_ok_and(|s| s.as_ref().is_some_and(|s| s.contains(dir)))
    {
        return Ok(());
    }
    let data = data_dir();
    if let Some(parent) = dir.parent().filter(|p| p.starts_with(&data)) {
        secure_dir(parent)?;
    }
    crate::win::private_dir(dir).map_err(|e| {
        kvt_core::trf!(
            "не удалось подготовить каталог {}: {e}",
            "couldn't prepare the folder {}: {e}",
            dir.display()
        )
    })?;
    if let Ok(mut secured) = SECURED.lock() {
        secured
            .get_or_insert_with(Default::default)
            .insert(dir.to_path_buf());
    }
    Ok(())
}

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

fn clear_marker(marker: &Path) {
    match std::fs::remove_file(marker) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "отметка kill switch не стёрта"),
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
    /// Ядро не смогло настроить IPv6 у адаптера: до перезапуска службы TUN
    /// собирается только с IPv4, чтобы следующие подключения не ждали 15 попыток.
    ipv6_failed: bool,
    /// Ядро завершилось с ошибкой, после которой положено переподключиться:
    /// `exited` положил её в `issues`, `handle_issue` переподключит.
    retry_after_exit: bool,
}

/// Отметка «kill switch включён» в каталоге `run` (см. `mark_kill_switch`).
const KILL_SWITCH_MARKER: &str = "kill-switch.on";

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
            retry_after_exit: false,
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
        // Адрес сервера — маскировщику и (в гибриде) в исключения winws — до остановки
        // прежнего ядра: пока его туннель жив, DNS отвечает. Потом при kill switch
        // прежние фильтры закрывают DNS всем, кроме ядра и службы, а имя за службу
        // спрашивает служба DNS-клиента Windows — запрос ждал бы 5 с и не дал IP.
        hide_server_addresses(&plan.server);
        let servers = match &plan.zapret {
            Some(_) => {
                crate::zapret::server_addresses(&plan.server.endpoints(), plan.server.port).await
            }
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
                forget_checked();
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
        if let Err(e) = self.enable_dns_guard(luid) {
            // Как и с kill switch: не оставляем соединение, у которого DNS уходит мимо.
            self.stop_running().await;
            tracing::error!(error = %e, "DNS мимо туннеля не закрыт");
            return Err(kvt_core::trf!(
                "Не удалось закрыть DNS-запросы мимо VPN, поэтому подключение остановлено. Подключитесь снова; если повторится — сохраните диагностику. ({e})",
                "Couldn't block DNS requests outside the VPN, so the connection was stopped. Connect again; if it happens again, save diagnostics. ({e})"
            ));
        }
        if plan.kill_switch {
            if let Err(e) = self.enable_kill_switch(&spec, luid) {
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
            spawn_rules_sync(self.paths.rules.clone(), background, force);
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
                .map_or(true, |r| matches!(r.child.try_wait(), Ok(Some(_))));
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

    /// Ядра и служба. Оба ядра: тестовое ядро проверки серверов бывает не тем,
    /// что подключено.
    fn trusted_apps(&self) -> Result<Vec<PathBuf>, String> {
        let service = std::env::current_exe().map_err(|e| e.to_string())?;
        Ok(vec![
            CoreSpec::new(CoreKind::Xray, &self.paths).exe,
            CoreSpec::new(CoreKind::SingBox, &self.paths).exe,
            service,
        ])
    }

    fn enable_dns_guard(&mut self, luid: u64) -> Result<(), String> {
        let apps = self.trusted_apps()?;
        let apps: Vec<&Path> = apps.iter().map(PathBuf::as_path).collect();
        let guard = DnsGuard::enable(&apps, luid).map_err(|e| e.to_string())?;
        if let Some(running) = self.running.as_mut() {
            running.dns_guard = Some(guard);
        }
        Ok(())
    }

    fn enable_kill_switch(&mut self, spec: &CoreSpec, luid: u64) -> Result<(), String> {
        let service = std::env::current_exe().map_err(|e| e.to_string())?;
        // «Гибрид»: пакеты, которые winws отправляет заново, Windows приписывает ядру
        // системы — kill switch должен их пропускать (см. `wfp::KillSwitch::enable`).
        let hybrid = self.zapret.is_some();
        let apps = [spec.exe.as_path(), service.as_path()];
        let ks = KillSwitch::enable(&apps, Some(luid), hybrid).map_err(|e| e.to_string())?;
        tracing::info!("kill switch включён");
        self.kill_switch = Some(ks);
        self.mark_kill_switch(true);
        Ok(())
    }

    /// Отметка на диске «kill switch включён»: фильтры WFP динамические и пропадают
    /// вместе с процессом службы, а отметка переживает падение — по ней служба после
    /// перезапуска снова закрывает интернет (`restore_kill_switch`).
    fn mark_kill_switch(&self, on: bool) {
        let marker = self.paths.run.join(KILL_SWITCH_MARKER);
        let result = if on {
            std::fs::write(&marker, b"")
        } else {
            match std::fs::remove_file(&marker) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                other => other,
            }
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, on, "отметка kill switch не записана");
        }
    }

    /// Служба запустилась, а отметка kill switch осталась: прошлый процесс упал с
    /// включённым kill switch. Интернет снова закрывается до решения окна
    /// («Подключить» или «Отключить»). Отметка с прошлой загрузки Windows (выключили
    /// питание) не действует: после перезагрузки закрытого интернета никто не ждёт.
    pub fn restore_kill_switch(&mut self) -> bool {
        // Каталог только для SYSTEM и администраторов: чужой каталог `private_dir`
        // убирает в сторону вместе с отметкой.
        if secure_dir(&self.paths.run).is_err() {
            return false;
        }
        let marker = self.paths.run.join(KILL_SWITCH_MARKER);
        let Ok(written) = std::fs::metadata(&marker).and_then(|m| m.modified()) else {
            return false;
        };
        if crate::win::boot_time().map_or(true, |boot| written < boot) {
            tracing::info!("отметка kill switch с прошлой загрузки Windows — не восстанавливаем");
            self.mark_kill_switch(false);
            return false;
        }
        let enabled = self.trusted_apps().and_then(|apps| {
            let apps: Vec<&Path> = apps.iter().map(PathBuf::as_path).collect();
            KillSwitch::enable(&apps, None, false).map_err(|e| e.to_string())
        });
        match enabled {
            Ok(ks) => {
                tracing::warn!("служба перезапустилась после сбоя: kill switch восстановлен");
                self.kill_switch = Some(ks);
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "kill switch после сбоя не восстановлен");
                false
            }
        }
    }

    async fn check_and_spawn(
        &self,
        spec: &CoreSpec,
        config: &Path,
        fingerprint: u64,
    ) -> Result<(Child, Job), String> {
        let start = std::time::Instant::now();
        if !already_checked(fingerprint) {
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
            remember_checked(fingerprint);
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

    pub fn kill_switch_active(&self) -> bool {
        self.kill_switch.is_some()
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

struct CoreSpec {
    exe: PathBuf,
    config_name: &'static str,
    core: CoreKind,
    env: Vec<(OsString, OsString)>,
    run_dir: PathBuf,
}

impl CoreSpec {
    fn new(core: CoreKind, paths: &Paths) -> Self {
        match core {
            CoreKind::Xray => Self {
                exe: paths.cores.join("xray.exe"),
                config_name: "xray.json",
                core,
                // geoip.dat и itdog-geosite.dat лежат в каталоге списков.
                env: vec![(
                    "XRAY_LOCATION_ASSET".into(),
                    paths.rules.clone().into_os_string(),
                )],
                run_dir: paths.run.clone(),
            },
            CoreKind::SingBox => Self {
                exe: paths.cores.join("sing-box.exe"),
                config_name: "sing-box.json",
                core,
                env: Vec::new(),
                run_dir: paths.run.clone(),
            },
        }
    }

    fn check_args(&self, config: &Path) -> Vec<OsString> {
        match self.core {
            CoreKind::Xray => vec!["run".into(), "-test".into(), "-c".into(), config.into()],
            CoreKind::SingBox => vec!["check".into(), "-c".into(), config.into()],
        }
    }

    fn run_args(&self, config: &Path) -> Vec<OsString> {
        match self.core {
            CoreKind::Xray => vec!["run".into(), "-c".into(), config.into()],
            CoreKind::SingBox => vec![
                "run".into(),
                "-c".into(),
                config.into(),
                "-D".into(),
                self.run_dir.clone().into_os_string(),
                "--disable-color".into(),
            ],
        }
    }
}

/// Физический интерфейс для winws в гибриде. Сразу после остановки прежнего ядра
/// маршрут ещё может вести в старый TUN — ждём, пока система выберет другой.
async fn physical_interface() -> Option<u32> {
    for _ in 0..20 {
        let tun = wfp::interface_index(TUN_INTERFACE);
        match wfp::best_interface(ROUTE_PROBE) {
            Some(best) if Some(best) != tun => return Some(best),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    None
}

/// Запускает процесс в Job Object, собирает его вывод в кольцевой лог и
/// проверяет, что он не упал сразу после старта. `ready` — признак, что процесс
/// заработал и `STARTUP_GRACE` можно не дожидаться (`|| false` — ждать весь срок).
pub async fn spawn_supervised(
    mut cmd: Command,
    log: &Log,
    what: &str,
    watch: Option<(CoreKind, Issues)>,
    ready: impl Fn() -> bool,
) -> Result<(Child, Job), String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| {
        kvt_core::trf!(
            "не удалось запустить {what}: {e}",
            "couldn't start {what}: {e}"
        )
    })?;
    let job = Job::kill_on_close().map_err(|e| format!("job: {e}"))?;
    if let Some(handle) = child.raw_handle() {
        job.assign(handle).map_err(|e| format!("job: {e}"))?;
    }
    if let Some(out) = child.stdout.take() {
        tokio::spawn(collect(out, Arc::clone(log), watch.clone()));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(collect(err, Arc::clone(log), watch));
    }
    let deadline = tokio::time::Instant::now() + STARTUP_GRACE;
    let exited = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break None;
        }
        // `Child::wait` можно прерывать таймаутом: статус не теряется.
        match tokio::time::timeout(left.min(READY_POLL), child.wait()).await {
            Ok(status) => break Some(status),
            Err(_) if ready() => break None,
            Err(_) => {}
        }
    };
    if let Some(status) = exited {
        // Даём читателям лога дочитать последние строки.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let last = log.lock().map(|l| {
            l.iter()
                .rev()
                .take(3)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ")
        });
        return Err(kvt_core::trf!(
            "{what} завершился сразу после запуска ({}): {}",
            "{what} exited right after starting ({}): {}",
            status.map(|s| s.to_string()).unwrap_or_default(),
            last.unwrap_or_default()
        ));
    }
    Ok((child, job))
}

async fn collect<R: AsyncRead + Unpin>(reader: R, log: Log, watch: Option<(CoreKind, Issues)>) {
    let mut watcher = core_errors::Watcher::default();
    let mut logged: std::collections::HashMap<&'static str, std::time::Instant> =
        std::collections::HashMap::new();
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    while let Some(line) = next_line(&mut reader, &mut buf).await {
        // Обрезка — после маскировки: разрезанный пароль или UUID маскировщик бы не узнал.
        let line = clip(kvt_core::redact::text(&line), MAX_LINE);
        if let Some((core, issues)) = &watch {
            // На диск попадают только строки, которые узнало правило. У правил «только
            // записать» (таймауты, DNS) в строке бывают адреса сайтов, которые открывал
            // пользователь, поэтому от них пишется лишь код — не чаще раза в минуту.
            if let Some(rule) = core_errors::classify(*core, &line) {
                let due = logged
                    .get(rule.code.as_str())
                    .map_or(true, |t| t.elapsed() >= Duration::from_secs(60));
                if rule.action != core_errors::Action::Log {
                    tracing::warn!(code = %rule.code, "ядро: {line}");
                } else if due {
                    tracing::info!(code = %rule.code, "ядро: {}", rule.text);
                }
                if due {
                    logged.insert(rule.code.as_str(), std::time::Instant::now());
                }
            }
            if let Some(hit) = watcher.observe(*core, &line, std::time::Instant::now()) {
                if hit.action != core_errors::Action::Log {
                    if let Ok(mut slot) = issues.lock() {
                        slot.get_or_insert(hit);
                    }
                }
            }
        }
        tracing::debug!(target: "core", "{line}");
        if let Ok(mut l) = log.lock() {
            if l.len() >= LOG_LINES {
                l.pop_front();
            }
            l.push_back(line);
        }
    }
}

/// Не длиннее `max` байт, по границе символа: 200 строк журнала ядра должны
/// помещаться в ответ службы (кадр IPC — 1 МБ).
fn clip(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
    s
}

/// Следующая строка вывода процесса; `None` — вывод закрыт. Байты не в UTF-8
/// (домен из перехваченного трафика, текст чужой ошибки) заменяются, а не
/// обрывают чтение: `Lines` на такой строке возвращает ошибку, после неё служба
/// перестала бы читать ядро — правила ошибок и журнал ядра молча выключились бы
/// до конца сеанса.
async fn next_line<R: AsyncBufRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> Option<String> {
    buf.clear();
    match reader.read_until(b'\n', buf).await {
        Ok(0) => None,
        Ok(_) => {
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            Some(String::from_utf8_lossy(buf).into_owned())
        }
        Err(e) => {
            tracing::warn!(error = %e, "вывод процесса не читается");
            None
        }
    }
}

/// После уборки устройства Wintun интерфейс KVT исчезает не мгновенно — ждём до
/// 3 с, чтобы новое ядро не застало прежний. Интерфейса нет — возврат сразу; не
/// исчез (уборка не удалась) — запускаем всё равно: Xray откроет существующий
/// адаптер, а если упрётся в «адаптер занят», переподключит `exited`.
async fn wait_adapter_removed() {
    const STEP: Duration = Duration::from_millis(100);
    let mut waited = Duration::ZERO;
    while wfp::interface_luid(TUN_INTERFACE).is_some() {
        if waited >= Duration::from_secs(3) {
            tracing::warn!("адаптер KVT не исчез за 3 с после остановки ядра");
            return;
        }
        tokio::time::sleep(STEP).await;
        waited += STEP;
    }
    if !waited.is_zero() {
        tracing::info!(
            ms = waited.as_millis() as u64,
            "дождались удаления адаптера KVT"
        );
    }
}

/// Устройства Wintun, оставшиеся от прежнего запуска ядра (см.
/// [`crate::win::remove_stale_wintun`]). Без этого на части компьютеров каждое
/// подключение после «Отключить» 15 с ждало Wintun и падало с «адаптер занят».
async fn remove_stale_wintun_devices() {
    let results = tokio::task::spawn_blocking(|| {
        crate::win::KVT_WINTUN_DEVICES
            .iter()
            .map(|id| (*id, crate::win::remove_stale_wintun(id)))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    for (device, result) in results {
        match result {
            Ok(true) => tracing::info!(device, "убрано оставшееся устройство Wintun"),
            Ok(false) => {}
            // Не мешает подключению: ядро попробует само, а при сбое KVT переподключится.
            Err(e) => tracing::warn!(device, error = %e, "не удалось убрать устройство Wintun"),
        }
    }
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// Адрес сервера — маскировщику журналов до запуска ядра: в строках ядра его не
/// придётся угадывать. Сервер загрузки XHTTP (`downloadSettings`) скрывается так же.
///
/// Адреса только добавляются: прежнее ядро ещё допишет строки о прежнем сервере, а
/// поздний ответ DNS по нему не должен вытеснить новый. Прежние IP имени — сразу,
/// свежие — в фоне: при переподключении с kill switch системный DNS может не
/// отвечать, и ждать его нельзя.
fn hide_server_addresses(server: &kvt_core::Server) {
    let endpoints = server.endpoints();
    kvt_core::redact::add_servers(&endpoints);
    kvt_core::redact::set_secrets(server.secrets());
    for host in endpoints {
        if host.parse::<std::net::IpAddr>().is_err() {
            kvt_core::redact::add_servers(
                crate::net::known_ips(&host)
                    .iter()
                    .map(std::net::IpAddr::to_string),
            );
            let port = server.port;
            tokio::spawn(async move {
                let ips = crate::net::resolve(&host, port).await;
                kvt_core::redact::add_servers(ips.iter().map(std::net::IpAddr::to_string));
            });
        }
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
fn spawn_rules_sync(dir: PathBuf, files: Vec<rulesync::RuleFile>, force: bool) {
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
            forget_checked();
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

    #[tokio::test]
    async fn instant_exit_is_reported() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo bad config & exit 3"]);
        let Err(err) = spawn_supervised(cmd, &log, "test", None, || false).await else {
            panic!("ожидалась ошибка")
        };
        assert!(err.contains("bad config"), "{err}");
    }

    #[tokio::test]
    async fn long_running_process_is_kept() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo started & ping -n 30 127.0.0.1 >nul"]);
        let (mut child, _job) = spawn_supervised(cmd, &log, "test", None, || false)
            .await
            .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        assert!(log.lock().unwrap().iter().any(|l| l.contains("started")));
        child.kill().await.unwrap();
    }

    #[tokio::test]
    async fn ready_process_is_released_early() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "ping -n 30 127.0.0.1 >nul"]);
        let start = std::time::Instant::now();
        let (mut child, _job) = spawn_supervised(cmd, &log, "test", None, || true)
            .await
            .unwrap();
        assert!(start.elapsed() < STARTUP_GRACE / 2, "{:?}", start.elapsed());
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
    }

    #[tokio::test]
    async fn exit_is_reported_until_ready() {
        // Готовность наступает позже падения — падение не теряется.
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo bad config & exit 3"]);
        let start = std::time::Instant::now();
        let ready = move || start.elapsed() > Duration::from_millis(1500);
        let Err(err) = spawn_supervised(cmd, &log, "test", None, ready).await else {
            panic!("ожидалась ошибка")
        };
        assert!(err.contains("bad config"), "{err}");
    }

    /// Строка не в UTF-8 не обрывает чтение: следующие строки ядра по-прежнему
    /// доходят до журнала и правил ошибок.
    #[tokio::test]
    async fn invalid_utf8_does_not_stop_reading() {
        let log = Log::default();
        let input: &[u8] = b"first\r\nbad \xFF\xFE byte\nlast";
        collect(input, Arc::clone(&log), None).await;
        let lines: Vec<String> = log.lock().unwrap().iter().cloned().collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(lines[0], "first");
        assert!(lines[1].starts_with("bad ") && lines[1].ends_with(" byte"));
        assert_eq!(lines[2], "last");
    }

    /// Очень длинная строка ядра хранится обрезанной — журнал помещается в ответ службы.
    #[tokio::test]
    async fn long_lines_are_clipped() {
        let log = Log::default();
        let input = format!("{}\nnext\n", "ж".repeat(MAX_LINE));
        collect(input.as_bytes(), Arc::clone(&log), None).await;
        let lines: Vec<String> = log.lock().unwrap().iter().cloned().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].len() <= MAX_LINE + '…'.len_utf8(),
            "{}",
            lines[0].len()
        );
        assert!(lines[0].ends_with('…'));
        assert_eq!(lines[1], "next");
    }

    /// UUID на месте обрезки скрывается целиком, а не остаётся видна его половина.
    #[tokio::test]
    async fn secrets_are_hidden_before_clipping() {
        let log = Log::default();
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        // Короткие слова: длинным токеном маскировщик скрыл бы всё и так.
        let input = format!("{}{uuid}\n", "a ".repeat((MAX_LINE - 10) / 2));
        collect(input.as_bytes(), Arc::clone(&log), None).await;
        let line = log.lock().unwrap().front().cloned().unwrap();
        assert!(!line.contains("123e4567"), "{line}");
    }

    #[test]
    fn checked_configs_are_remembered_and_forgotten() {
        let a = config_fingerprint(CoreKind::Xray, b"{\"a\":1}");
        let b = config_fingerprint(CoreKind::SingBox, b"{\"a\":1}");
        assert_ne!(a, b, "отпечаток зависит от ядра");
        assert!(!already_checked(a));
        remember_checked(a);
        assert!(already_checked(a) && !already_checked(b));
        for i in 0..CHECKED_MAX as u64 {
            remember_checked(i);
        }
        assert!(!already_checked(a), "старые отпечатки вытесняются");
        remember_checked(b);
        forget_checked();
        assert!(!already_checked(b));
    }
}
