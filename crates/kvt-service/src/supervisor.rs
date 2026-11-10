//! Запуск и остановка ядра. Конфиг строится службой из проверенного плана,
//! проверяется самим ядром, живёт на диске только до старта ядра (в каталоге,
//! доступном лишь SYSTEM и администраторам), а процесс ядра помещается в
//! Job Object и не переживает службу.

use crate::net::NetClient;
use crate::wfp::{self, KillSwitch};
use crate::win::Job;
use kvt_core::compile::{compile, CompileInput, TUN_INTERFACE};
use kvt_core::core_errors::{self, Triggered};
use kvt_core::core_select::CoreKind;
use kvt_core::ipc::{ConnectPlan, ZapretPlan};
use kvt_core::rulesync;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Сколько ждём после запуска, чтобы поймать мгновенное падение ядра.
const STARTUP_GRACE: Duration = Duration::from_secs(2);
const LOG_LINES: usize = 200;

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

/// Каталог только для SYSTEM (S-1-5-18) и администраторов (S-1-5-32-544).
/// SID вместо имён — имена групп локализованы («Администраторы»).
pub(crate) fn secure_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("не удалось создать {}: {e}", dir.display()))?;
    let status = std::process::Command::new("icacls")
        .arg(dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/Q",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("icacls: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("не удалось ограничить доступ к {}", dir.display()))
    }
}

pub type Log = Arc<Mutex<VecDeque<String>>>;
/// Сработавшее правило ошибок ядра, которое ещё не обработано.
pub type Issues = Arc<Mutex<Option<Triggered>>>;

struct Running {
    child: Child,
    _job: Job,
}

pub struct Supervisor {
    paths: Paths,
    running: Option<Running>,
    /// Живёт отдельно от процесса ядра: если ядро упало, блокировка остаётся
    /// до явного «Отключить».
    kill_switch: Option<KillSwitch>,
    /// winws: в гибриде рядом с ядром, в режиме zapret — один.
    zapret: Option<crate::zapret::Winws>,
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

/// Код правила из `presets/core-errors.json`: ядро не может задать адаптеру IPv6.
const TUN_IPV6: &str = "tun_ipv6";

impl Supervisor {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            running: None,
            kill_switch: None,
            zapret: None,
            log: Log::default(),
            issues: Issues::default(),
            last_plan: None,
            reconnected: false,
            ipv6_failed: false,
            retry_after_exit: false,
        }
    }

    pub fn recent_log(&self, n: usize) -> Vec<String> {
        let log = self.log.lock().map(|l| l.clone()).unwrap_or_default();
        log.iter().rev().take(n).rev().cloned().collect()
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
            self.zapret = None;
        }
        if let (Err(e), Some(previous)) = (&result, previous) {
            if self.kill_switch.is_none() {
                // Защиту включали до переподключения — не снимаем её из-за сбоя.
                self.kill_switch = Some(previous);
                return Err(format!(
                    "{e}. Kill switch держит интернет закрытым — нажмите «Отключить» или подключитесь заново"
                ));
            }
        }
        result
    }

    async fn start_inner(&mut self, plan: &ConnectPlan) -> Result<(), String> {
        self.stop().await;
        remove_stale_wintun_devices().await;
        wait_adapter_removed().await;
        plan.routing.validate().map_err(|e| e.to_string())?;
        if !crate::win::is_elevated() {
            tracing::error!("служба без прав администратора — TUN не создать");
            return Err("Службе KVT не хватает прав, чтобы создать сетевой адаптер. Переустановите KVT — служба должна работать от имени системы."
                .into());
        }
        hide_server_addresses(&plan.server);
        secure_dir(&self.paths.rules)?;
        secure_dir(&self.paths.run)?;

        // Списки: докачиваем недостающие; при сбое сети работаем на прежних версиях.
        let files = rulesync::required_files(&plan.routing, plan.core);
        let http = NetClient::new(kvt_core::netlog::Purpose::Rules).map_err(|e| e.to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let report = rulesync::sync(&http, &self.paths.rules, &files, now, false).await;
        for (file, err) in &report.failed {
            tracing::warn!(file, err, "список не обновлён");
        }
        if let Some(missing) = files
            .iter()
            .find(|f| !self.paths.rules.join(&f.local).exists())
        {
            return Err(format!(
                "Не удалось загрузить список «{}» с GitHub. Проверьте интернет и подключитесь снова.",
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

        if let Some(zp) = &plan.zapret {
            // winws — до ядра, пока трафик ещё идёт через физический интерфейс.
            let interface = physical_interface().await;
            self.zapret = Some(
                crate::zapret::start(
                    &self.paths,
                    zp,
                    &plan.routing.zapret_hostlist(),
                    std::slice::from_ref(&plan.server.address),
                    interface,
                    &self.log,
                )
                .await?,
            );
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

        let spec = CoreSpec::new(plan.core, &self.paths);
        let config_path = self.paths.run.join(spec.config_name);
        std::fs::write(&config_path, config)
            .map_err(|e| format!("не удалось записать конфиг: {e}"))?;
        if let Ok(mut issues) = self.issues.lock() {
            *issues = None;
        }
        let result = self.check_and_spawn(&spec, &config_path).await;
        // Секреты на диске не задерживаются: ядро уже прочитало конфиг (или не запустилось).
        let _ = std::fs::remove_file(&config_path);
        let (child, job) = result?;
        self.running = Some(Running { child, _job: job });

        if plan.kill_switch {
            if let Err(e) = self.enable_kill_switch(&spec).await {
                // Защиту обещали, но включить не смогли — не оставляем «полузащищённое» соединение.
                self.stop().await;
                tracing::error!(error = %e, "kill switch не включился");
                return Err(format!(
                    "Не удалось включить kill switch, поэтому подключение остановлено. Подключитесь снова; если повторится — выключите kill switch в настройках и сохраните диагностику. ({e})"
                ));
            }
        }
        tracing::info!(core = ?plan.core, kill_switch = plan.kill_switch, "подключено");
        if !retry.is_empty() {
            spawn_rules_retry(self.paths.rules.clone(), retry);
        }
        Ok(())
    }

    /// Обрабатывает сработавшее правило ошибок ядра. `Some(текст)` — подключение
    /// остановлено, текст — причина для пользователя.
    pub async fn handle_issue(&mut self) -> Option<String> {
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
                Some(format!("{} Подключение остановлено.", issue.text))
            }
        }
    }

    /// Останавливает ядро и zapret, но не kill switch: как при падении ядра,
    /// интернет мимо туннеля не открывается до явного «Отключить».
    async fn halt_core(&mut self) {
        if let Some(mut running) = self.running.take() {
            let _ = running.child.kill().await;
        }
        self.zapret = None;
    }

    /// VPN-ядро сейчас работает.
    pub fn vpn_running(&self) -> bool {
        self.running.is_some()
    }

    async fn enable_kill_switch(&mut self, spec: &CoreSpec) -> Result<(), String> {
        // Интерфейс TUN появляется не мгновенно после старта ядра: Wintun сам ждёт
        // устройство до 15 с. Ждём дольше, но не дольше, чем живёт ядро.
        let mut luid = None;
        for _ in 0..200 {
            luid = wfp::interface_luid(TUN_INTERFACE);
            if luid.is_some() {
                break;
            }
            let exited = self
                .running
                .as_mut()
                .map_or(true, |r| matches!(r.child.try_wait(), Ok(Some(_))));
            if exited {
                let last = self.recent_log(1).pop().unwrap_or_default();
                return Err(format!("VPN-ядро остановилось, не создав адаптер: {last}"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let luid = luid.ok_or("интерфейс TUN не появился за 20 с")?;
        let service = std::env::current_exe().map_err(|e| e.to_string())?;
        // «Гибрид»: пакеты, которые winws отправляет заново, Windows приписывает ядру
        // системы — kill switch должен их пропускать (см. `wfp::KillSwitch::add_rules`).
        let hybrid = self.zapret.is_some();
        let apps = [spec.exe.as_path(), service.as_path()];
        let ks = KillSwitch::enable(&apps, Some(luid), hybrid).map_err(|e| e.to_string())?;
        tracing::info!("kill switch включён");
        self.kill_switch = Some(ks);
        Ok(())
    }

    async fn check_and_spawn(
        &self,
        spec: &CoreSpec,
        config: &Path,
    ) -> Result<(Child, Job), String> {
        let check = Command::new(&spec.exe)
            .args(spec.check_args(config))
            .envs(spec.env.clone())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .await
            .map_err(|e| format!("не удалось запустить {}: {e}", spec.exe.display()))?;
        if !check.status.success() {
            let text = String::from_utf8_lossy(&[check.stdout, check.stderr].concat()).into_owned();
            let detail = tail(&kvt_core::redact::text(&text), 3);
            tracing::error!(%detail, "ядро отвергло конфигурацию");
            return Err(format!(
                "VPN-ядро не приняло настройки этого сервера — возможно, в ключе неподдерживаемые параметры. Выберите другой сервер или сохраните диагностику. ({detail})"
            ));
        }
        let mut cmd = Command::new(&spec.exe);
        cmd.args(spec.run_args(config))
            .envs(spec.env.clone())
            .current_dir(&self.paths.run);
        spawn_supervised(
            cmd,
            &self.log,
            "ядро",
            Some((spec.core, Arc::clone(&self.issues))),
        )
        .await
    }

    /// Только zapret, без VPN: winws на всех интерфейсах.
    pub async fn start_zapret(&mut self, plan: &ZapretPlan) -> Result<String, String> {
        self.stop().await;
        if !crate::win::is_elevated() {
            return Err(
                "Службе KVT не хватает прав, чтобы запустить zapret. Переустановите KVT — служба должна работать от имени системы."
                    .into(),
            );
        }
        let winws =
            crate::zapret::start(&self.paths, plan, &plan.domains, &[], None, &self.log).await?;
        let strategy = winws.strategy.clone();
        self.zapret = Some(winws);
        Ok(strategy)
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn zapret_pid(&self) -> Option<u32> {
        self.zapret.as_ref().and_then(|z| z.pid())
    }

    pub async fn stop(&mut self) {
        if let Some(mut running) = self.running.take() {
            let _ = running.child.kill().await;
            tracing::info!("ядро остановлено");
        }
        if self.zapret.take().is_some() {
            tracing::info!("zapret остановлен");
        }
        if self.kill_switch.take().is_some() {
            tracing::info!("kill switch выключен");
        }
    }

    pub fn kill_switch_active(&self) -> bool {
        self.kill_switch.is_some()
    }

    /// Если ядро или zapret завершились сами — причина (последние строки лога).
    pub fn exited(&mut self) -> Option<String> {
        if let Some(reason) = self.zapret.as_mut().and_then(crate::zapret::Winws::exited) {
            self.zapret = None;
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
                            text: rule.text.clone(),
                            action: rule.action,
                        });
                        self.retry_after_exit = true;
                        return None;
                    }
                }
                let known = rule.map(|r| r.text.clone());
                Some(known.unwrap_or_else(|| format!("VPN-ядро неожиданно остановилось: {last}")))
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
    let probe = std::net::Ipv4Addr::new(8, 8, 8, 8);
    for _ in 0..20 {
        let tun = wfp::interface_index(TUN_INTERFACE);
        match wfp::best_interface(probe) {
            Some(best) if Some(best) != tun => return Some(best),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    None
}

/// Запускает процесс в Job Object, собирает его вывод в кольцевой лог и
/// проверяет, что он не упал сразу после старта.
pub async fn spawn_supervised(
    mut cmd: Command,
    log: &Log,
    what: &str,
    watch: Option<(CoreKind, Issues)>,
) -> Result<(Child, Job), String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("не удалось запустить {what}: {e}"))?;
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
    if let Ok(status) = tokio::time::timeout(STARTUP_GRACE, child.wait()).await {
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
        return Err(format!(
            "{what} завершился сразу после запуска ({}): {}",
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
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = kvt_core::redact::text(&line);
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
/// придётся угадывать. IP, в которые разрешается имя, добавляются в фоне: при
/// переподключении с kill switch системный DNS может не отвечать, и ждать его нельзя.
fn hide_server_addresses(server: &kvt_core::Server) {
    kvt_core::redact::set_servers([server.address.as_str()]);
    if server.address.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    let host = (server.address.clone(), server.port);
    tokio::spawn(async move {
        let lookup = tokio::net::lookup_host(host);
        if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_secs(5), lookup).await {
            kvt_core::redact::add_servers(addrs.map(|a| a.ip().to_string()));
        }
    });
}

/// Повтор загрузки списков через туннель после подключения. Ядро уже работает на
/// прежних версиях; новые применятся при следующем подключении.
fn spawn_rules_retry(dir: PathBuf, files: Vec<rulesync::RuleFile>) {
    tokio::spawn(async move {
        // Даём TUN и маршрутам подняться.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Ok(http) = NetClient::new(kvt_core::netlog::Purpose::Rules) else {
            return;
        };
        let http = http.with_tunnel_fallback();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let report = rulesync::sync(&http, &dir, &files, now, true).await;
        for (file, err) in &report.failed {
            tracing::warn!(file, err, "список не обновился и через туннель");
        }
        for file in &report.updated {
            tracing::info!(file, "список обновлён через туннель");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn instant_exit_is_reported() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo bad config & exit 3"]);
        let Err(err) = spawn_supervised(cmd, &log, "test", None).await else {
            panic!("ожидалась ошибка")
        };
        assert!(err.contains("bad config"), "{err}");
    }

    #[tokio::test]
    async fn long_running_process_is_kept() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo started & ping -n 30 127.0.0.1 >nul"]);
        let (mut child, _job) = spawn_supervised(cmd, &log, "test", None).await.unwrap();
        assert!(child.try_wait().unwrap().is_none());
        assert!(log.lock().unwrap().iter().any(|l| l.contains("started")));
        child.kill().await.unwrap();
    }
}
