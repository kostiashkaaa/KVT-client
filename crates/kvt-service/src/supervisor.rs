//! Запуск и остановка ядра. Конфиг строится службой из проверенного плана,
//! проверяется самим ядром, живёт на диске только до старта ядра (в каталоге,
//! доступном лишь SYSTEM и администраторам), а процесс ядра помещается в
//! Job Object и не переживает службу.

use crate::net::NetClient;
use crate::wfp::{self, KillSwitch};
use crate::win::Job;
use kvt_core::compile::{compile, CompileInput, DnsPlan, TUN_INTERFACE};
use kvt_core::core_select::CoreKind;
use kvt_core::ipc::ConnectPlan;
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
}

impl Paths {
    pub fn standard() -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let exe_dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        let data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("KVT");
        Ok(Self {
            cores: exe_dir.join("cores"),
            rules: data.join("rules"),
            run: data.join("run"),
        })
    }
}

/// Каталог только для SYSTEM (S-1-5-18) и администраторов (S-1-5-32-544).
/// SID вместо имён — имена групп локализованы («Администраторы»).
fn secure_dir(dir: &Path) -> Result<(), String> {
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
    log: Log,
}

impl Supervisor {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            running: None,
            kill_switch: None,
            log: Log::default(),
        }
    }

    pub fn recent_log(&self, n: usize) -> Vec<String> {
        let log = self.log.lock().map(|l| l.clone()).unwrap_or_default();
        log.iter().rev().take(n).rev().cloned().collect()
    }

    pub async fn start(&mut self, plan: &ConnectPlan) -> Result<(), String> {
        self.stop().await;
        plan.routing.validate().map_err(|e| e.to_string())?;
        if !crate::win::is_elevated() {
            return Err("Служба запущена без прав администратора: без них нельзя создать TUN.                         Запустите `kvt-service --console` из терминала администратора."
                .into());
        }
        secure_dir(&self.paths.rules)?;
        secure_dir(&self.paths.run)?;

        // Списки: докачиваем недостающие; при сбое сети работаем на прежних версиях.
        let files = rulesync::required_files(&plan.routing, plan.core);
        let http = NetClient::new().map_err(|e| e.to_string())?;
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
                "Не удалось загрузить список «{}». Проверьте интернет.",
                missing.local
            ));
        }

        let rules = self.paths.rules.to_string_lossy().replace('\\', "/");
        let dns = DnsPlan::default();
        let compiled = compile(
            plan.core,
            &CompileInput {
                server: &plan.server,
                routing: &plan.routing,
                dns: &dns,
                rule_set_dir: &rules,
            },
        )
        .map_err(|e| e.to_string())?;
        let config = serde_json::to_vec(&compiled.config).map_err(|e| e.to_string())?;

        let spec = CoreSpec::new(plan.core, &self.paths);
        let config_path = self.paths.run.join(spec.config_name);
        std::fs::write(&config_path, config)
            .map_err(|e| format!("не удалось записать конфиг: {e}"))?;
        let result = self.check_and_spawn(&spec, &config_path).await;
        // Секреты на диске не задерживаются: ядро уже прочитало конфиг (или не запустилось).
        let _ = std::fs::remove_file(&config_path);
        let (child, job) = result?;
        self.running = Some(Running { child, _job: job });

        if plan.kill_switch {
            if let Err(e) = self.enable_kill_switch(&spec).await {
                // Защиту обещали, но включить не смогли — не оставляем «полузащищённое» соединение.
                self.stop().await;
                return Err(format!("Не удалось включить kill switch: {e}"));
            }
        }
        Ok(())
    }

    async fn enable_kill_switch(&mut self, spec: &CoreSpec) -> Result<(), String> {
        // Интерфейс TUN появляется не мгновенно после старта ядра.
        let mut luid = None;
        for _ in 0..50 {
            luid = wfp::interface_luid(TUN_INTERFACE);
            if luid.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let luid = luid.ok_or("интерфейс TUN не появился")?;
        let service = std::env::current_exe().map_err(|e| e.to_string())?;
        let ks = KillSwitch::enable(&[spec.exe.as_path(), service.as_path()], Some(luid))
            .map_err(|e| e.to_string())?;
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
            return Err(format!(
                "Ядро отвергло конфигурацию: {}",
                tail(&mask_secrets(&text), 3)
            ));
        }
        let mut cmd = Command::new(&spec.exe);
        cmd.args(spec.run_args(config))
            .envs(spec.env.clone())
            .current_dir(&self.paths.run);
        spawn_supervised(cmd, &self.log).await
    }

    pub async fn stop(&mut self) {
        if let Some(mut running) = self.running.take() {
            let _ = running.child.kill().await;
        }
        if self.kill_switch.take().is_some() {
            tracing::info!("kill switch выключен");
        }
    }

    pub fn kill_switch_active(&self) -> bool {
        self.kill_switch.is_some()
    }

    /// Если ядро завершилось само — причина (последние строки лога).
    pub fn exited(&mut self) -> Option<String> {
        let running = self.running.as_mut()?;
        match running.child.try_wait() {
            Ok(Some(status)) => {
                self.running = None;
                let last = self.recent_log(1).pop().unwrap_or_default();
                Some(format!("ядро остановилось ({status}): {last}"))
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

/// Запускает процесс в Job Object, собирает его вывод в кольцевой лог и
/// проверяет, что он не упал сразу после старта.
pub async fn spawn_supervised(mut cmd: Command, log: &Log) -> Result<(Child, Job), String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("не удалось запустить ядро: {e}"))?;
    let job = Job::kill_on_close().map_err(|e| format!("job: {e}"))?;
    if let Some(handle) = child.raw_handle() {
        job.assign(handle).map_err(|e| format!("job: {e}"))?;
    }
    if let Some(out) = child.stdout.take() {
        tokio::spawn(collect(out, Arc::clone(log)));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(collect(err, Arc::clone(log)));
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
            "Ядро завершилось сразу после запуска ({}): {}",
            status.map(|s| s.to_string()).unwrap_or_default(),
            last.unwrap_or_default()
        ));
    }
    Ok((child, job))
}

async fn collect<R: AsyncRead + Unpin>(reader: R, log: Log) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = mask_secrets(&line);
        tracing::debug!(target: "core", "{line}");
        if let Ok(mut l) = log.lock() {
            if l.len() >= LOG_LINES {
                l.pop_front();
            }
            l.push_back(line);
        }
    }
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// Маскирует UUID (идентификаторы пользователей VLESS) в строках лога.
pub fn mask_secrets(line: &str) -> String {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    'outer: while i < bytes.len() {
        if i + 36 <= bytes.len() {
            let mut pos = i;
            let mut ok = true;
            for (g, len) in GROUPS.iter().enumerate() {
                if !bytes[pos..pos + len].iter().all(u8::is_ascii_hexdigit) {
                    ok = false;
                    break;
                }
                pos += len;
                if g < 4 {
                    if bytes[pos] != b'-' {
                        ok = false;
                        break;
                    }
                    pos += 1;
                }
            }
            if ok {
                out.push_str("********-****-****-****-************");
                i += 36;
                continue 'outer;
            }
        }
        let ch = line[i..].chars().next().unwrap_or('?');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_masked() {
        let s = "failed for user b831381d-6324-4d53-ad4f-8cda48b30811 на сервере";
        assert_eq!(
            mask_secrets(s),
            "failed for user ********-****-****-****-************ на сервере"
        );
        assert_eq!(mask_secrets("обычная строка"), "обычная строка");
    }

    #[tokio::test]
    async fn instant_exit_is_reported() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo bad config & exit 3"]);
        let Err(err) = spawn_supervised(cmd, &log).await else {
            panic!("ожидалась ошибка")
        };
        assert!(err.contains("bad config"), "{err}");
    }

    #[tokio::test]
    async fn long_running_process_is_kept() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo started & ping -n 30 127.0.0.1 >nul"]);
        let (mut child, _job) = spawn_supervised(cmd, &log).await.unwrap();
        assert!(child.try_wait().unwrap().is_none());
        assert!(log.lock().unwrap().iter().any(|l| l.contains("started")));
        child.kill().await.unwrap();
    }
}
