//! Процесс ядра: аргументы запуска и проверки, запуск под присмотром (Job
//! Object, ранний выход), сбор вывода в журнал с маскировкой секретов.

use super::*;

pub(super) struct CoreSpec {
    pub(super) exe: PathBuf,
    pub(super) config_name: &'static str,
    pub(super) core: CoreKind,
    pub(super) env: Vec<(OsString, OsString)>,
    pub(super) run_dir: PathBuf,
}

impl CoreSpec {
    pub(super) fn new(core: CoreKind, paths: &Paths) -> Self {
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
            // Тот же sing-box, но сборка с AmneziaWG: свой exe и свой файл конфига.
            CoreKind::SingBoxAwg => Self {
                exe: paths.cores.join("sing-box-awg.exe"),
                config_name: "sing-box-awg.json",
                core,
                env: Vec::new(),
                run_dir: paths.run.clone(),
            },
        }
    }

    pub(super) fn check_args(&self, config: &Path) -> Vec<OsString> {
        match self.core {
            CoreKind::Xray => vec!["run".into(), "-test".into(), "-c".into(), config.into()],
            CoreKind::SingBox | CoreKind::SingBoxAwg => {
                vec!["check".into(), "-c".into(), config.into()]
            }
        }
    }

    pub(super) fn run_args(&self, config: &Path) -> Vec<OsString> {
        match self.core {
            CoreKind::Xray => vec!["run".into(), "-c".into(), config.into()],
            CoreKind::SingBox | CoreKind::SingBoxAwg => vec![
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
/// проверяет, что он не упал сразу после старта. `ready` — признак, что процесс
/// заработал и `STARTUP_GRACE` можно не дожидаться (`|| false` — ждать весь срок).
pub async fn spawn_supervised(
    mut cmd: Command,
    log: &Log,
    what: &str,
    watch: Option<(CoreKind, Issues)>,
    ready: impl Fn() -> bool,
) -> Result<(Child, Job), ProcessError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| ProcessError::Spawn {
        what: what.to_owned(),
        cause: e.to_string(),
    })?;
    let job = Job::kill_on_close().map_err(|e| ProcessError::Job(e.to_string()))?;
    if let Some(handle) = child.raw_handle() {
        job.assign(handle)
            .map_err(|e| ProcessError::Job(e.to_string()))?;
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
        return Err(ProcessError::ExitedEarly {
            what: what.to_owned(),
            status: status.map(|s| s.to_string()).unwrap_or_default(),
            last: last.unwrap_or_default(),
        });
    }
    Ok((child, job))
}

pub(super) async fn collect<R: AsyncRead + Unpin>(
    reader: R,
    log: Log,
    watch: Option<(CoreKind, Issues)>,
) {
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
                    .is_none_or(|t| t.elapsed() >= Duration::from_secs(60));
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
pub(super) fn clip(mut s: String, max: usize) -> String {
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
pub(super) async fn next_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Option<String> {
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

pub(super) fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn instant_exit_is_reported() {
        let log = Log::default();
        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "echo bad config & exit 3"]);
        let Err(err) = spawn_supervised(cmd, &log, "test", None, || false).await else {
            panic!("ожидалась ошибка")
        };
        assert!(err.to_string().contains("bad config"), "{err}");
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
        assert!(err.to_string().contains("bad config"), "{err}");
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
}
