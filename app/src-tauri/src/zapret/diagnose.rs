//! «Почему не работает?» для zapret: факты (конфликты, драйвер, комплект, прокси,
//! TCP timestamps) и вывод `conclude` — первый сбой и действие одной кнопкой.

use super::*;

// ── «Почему не работает?» для zapret ──

/// Программы, которые, по опыту Flowseal, мешают zapret.
pub(super) fn interferers() -> Vec<String> {
    let run = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
            .unwrap_or_default()
    };
    let tasks = run("tasklist", &["/FO", "CSV", "/NH"]);
    let services = run("sc", &["query"]);
    let mut out = Vec::new();
    if tasks.contains("\"adguardsvc.exe\"") {
        out.push(
            tr(
                "AdGuard — мешает Discord; добавьте Discord в исключения AdGuard",
                "AdGuard — interferes with Discord; add Discord to AdGuard's exclusions",
            )
            .to_owned(),
        );
    }
    if tasks.contains("\"avp.exe\"") {
        out.push(
            tr(
                "Антивирус Касперского — может блокировать WinDivert; добавьте папку KVT в исключения",
                "Kaspersky antivirus — may block WinDivert; add the KVT folder to exclusions",
            )
            .to_owned(),
        );
    }
    if services.contains("killer") {
        out.push(
            tr(
                "Killer Network Service — конфликтует с zapret; отключите его",
                "Killer Network Service — conflicts with zapret; turn it off",
            )
            .to_owned(),
        );
    }
    if services
        .lines()
        .any(|l| l.contains("intel") && l.contains("connectivity") && l.contains("network"))
    {
        out.push(
            tr(
                "Intel Connectivity Network Service — конфликтует с zapret",
                "Intel Connectivity Network Service — conflicts with zapret",
            )
            .to_owned(),
        );
    }
    if services.contains("tracsrvwrapper") || services.contains("epwd") {
        out.push(
            tr(
                "Check Point — конфликтует с zapret; его придётся удалить",
                "Check Point — conflicts with zapret; it has to be uninstalled",
            )
            .to_owned(),
        );
    }
    if services.contains("smartbyte") {
        out.push(
            tr(
                "SmartByte — конфликтует с zapret; отключите его в «Службах»",
                "SmartByte — conflicts with zapret; turn it off in Services",
            )
            .to_owned(),
        );
    }
    out
}

/// Системный прокси: браузер пойдёт через него, а не через zapret.
pub(super) fn system_proxy() -> Option<String> {
    let out = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let value = |name: &str| {
        text.lines()
            .find(|l| l.split_whitespace().next() == Some(name))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
    };
    (value("ProxyEnable").as_deref() == Some("0x1"))
        .then(|| value("ProxyServer").unwrap_or_default())
}

/// Включены ли TCP timestamps (`Get-NetTCPSetting` не зависит от языка Windows).
pub(super) fn tcp_timestamps_enabled() -> Option<bool> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetTCPSetting -SettingName Internet).Timestamps",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "Enabled" => Some(true),
        "Disabled" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretFix {
    /// Переустановить комплект и драйвер.
    Repair,
    StopConflicts,
    Autoselect,
    AllowTimestamps,
    /// Включить режим «Zapret».
    Enable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZapretDiagnosis {
    pub tone: Tone,
    pub title: String,
    pub detail: String,
    pub steps: Vec<Step>,
    pub fix: Option<ZapretFix>,
    pub check: Option<Check>,
}

#[derive(Debug, Clone, Default)]
pub struct ZapretFacts {
    /// `None` — служба не отвечает.
    pub service: Option<ServiceStatus>,
    pub info: Option<ZapretInfo>,
    pub conflicts: Vec<Conflict>,
    pub interferers: Vec<String>,
    pub proxy: Option<String>,
    /// Работающая стратегия; `None` — zapret выключен.
    pub running: Option<String>,
    pub needs_timestamps: bool,
    pub timestamps_allowed: bool,
    pub timestamps_enabled: Option<bool>,
    pub check: Option<Check>,
}

pub(super) fn step(
    steps: &mut Vec<Step>,
    title: &'static str,
    state: StepState,
    detail: impl Into<String>,
) {
    steps.push(Step {
        title,
        state,
        detail: detail.into(),
    });
}

pub fn conclude(f: &ZapretFacts) -> ZapretDiagnosis {
    let mut steps = Vec::new();
    let done = |steps: Vec<Step>, tone, title: &str, detail: String, fix| ZapretDiagnosis {
        tone,
        title: title.to_owned(),
        detail,
        steps,
        fix,
        check: f.check.clone(),
    };

    let Some(service) = &f.service else {
        step(
            &mut steps,
            tr("Служба KVT", "KVT service"),
            StepState::Fail,
            tr("Служба не отвечает", "The service doesn't respond"),
        );
        return done(
            steps,
            Tone::Error,
            tr("Служба KVT не запущена", "The KVT service isn't running"),
            tr(
                "zapret запускает служба KVT. Запустите её (для разработки — kvt-service --console от администратора).",
                "zapret is started by the KVT service. Start it (for development — kvt-service --console as administrator).",
            )
            .into(),
            None,
        );
    };
    step(
        &mut steps,
        tr("Служба KVT", "KVT service"),
        StepState::Ok,
        tr("Работает", "Working"),
    );

    match &f.info {
        Some(info) if !info.ok => {
            step(
                &mut steps,
                tr("Файлы zapret", "zapret files"),
                StepState::Fail,
                info.problem.clone().unwrap_or_default(),
            );
            return done(
                steps,
                Tone::Error,
                tr("Файлы zapret повреждены", "zapret files are damaged"),
                tr(
                    "Части комплекта нет или файлы изменены. Переустановка вернёт проверенные файлы и драйвер WinDivert.",
                    "Part of the bundle is missing or files were modified. Reinstalling restores the verified files and the WinDivert driver.",
                )
                .into(),
                Some(ZapretFix::Repair),
            );
        }
        Some(info) => step(
            &mut steps,
            tr("Файлы zapret", "zapret files"),
            StepState::Ok,
            trf!(
                "Flowseal {}, стратегий: {}",
                "Flowseal {}, strategies: {}",
                info.version,
                info.strategies
            ),
        ),
        None => {}
    }

    if !f.conflicts.is_empty() {
        let names: Vec<&str> = f.conflicts.iter().map(|c| c.name.as_str()).collect();
        step(
            &mut steps,
            tr("Другие обходы", "Other bypasses"),
            StepState::Fail,
            names.join(", "),
        );
        return done(
            steps,
            Tone::Error,
            tr("Работает другой обход блокировок", "Another block bypass is running"),
            trf!(
                "{} обрабатывает те же пакеты — вместе с zapret KVT ничего не открывается. KVT может их остановить, ничего не удаляя.",
                "{} handles the same packets — together with KVT's zapret nothing opens. KVT can stop them without deleting anything.",
                names.join(", ")
            ),
            Some(ZapretFix::StopConflicts),
        );
    }
    step(
        &mut steps,
        tr("Другие обходы", "Other bypasses"),
        StepState::Ok,
        tr("Не найдены", "None found"),
    );

    if let ServiceStatus::Failed { reason, .. } = service {
        if reason.contains("zapret") {
            step(&mut steps, "winws", StepState::Fail, reason.clone());
            return done(
                steps,
                Tone::Error,
                tr("zapret остановился", "zapret stopped"),
                tr(
                    "winws завершился сам — чаще всего мешает драйвер WinDivert или антивирус. Переустановка ставит драйвер заново.",
                    "winws exited on its own — usually the WinDivert driver or antivirus interferes. Reinstalling sets up the driver again.",
                )
                .into(),
                Some(ZapretFix::Repair),
            );
        }
    }

    let Some(strategy) = &f.running else {
        step(
            &mut steps,
            "zapret",
            StepState::Warning,
            tr("Выключен", "Off"),
        );
        return done(
            steps,
            Tone::Warning,
            tr("zapret выключен", "zapret is off"),
            tr(
                "Включите режим «Zapret» (без VPN) или «Гибрид» (YouTube и Discord через zapret, остальное через VPN).",
                "Turn on Zapret mode (no VPN) or Hybrid (YouTube and Discord via zapret, everything else via VPN).",
            )
            .into(),
            Some(ZapretFix::Enable),
        );
    };
    let title = kvt_core::zapret::title(strategy);
    step(
        &mut steps,
        "zapret",
        StepState::Ok,
        trf!(
            "Работает, стратегия «{title}»",
            "Working, strategy “{title}”"
        ),
    );

    for name in &f.interferers {
        step(
            &mut steps,
            tr("Мешающая программа", "Interfering app"),
            StepState::Warning,
            name.clone(),
        );
    }
    if let Some(proxy) = &f.proxy {
        step(
            &mut steps,
            tr("Системный прокси", "System proxy"),
            StepState::Warning,
            trf!(
                "Включён ({proxy}) — браузер пойдёт через него, а не через zapret",
                "On ({proxy}) — the browser will go through it instead of zapret"
            ),
        );
    }

    let Some(check) = &f.check else {
        return done(
            steps,
            Tone::Ok,
            tr("zapret работает", "zapret works"),
            String::new(),
            None,
        );
    };
    let state = if check.healthy() {
        StepState::Ok
    } else {
        StepState::Fail
    };
    step(
        &mut steps,
        tr("Discord и YouTube", "Discord and YouTube"),
        state,
        trf!(
            "Открывается {} из {} проверок",
            "{} of {} checks open",
            check.passed,
            check.max
        ),
    );
    if check.healthy() {
        let hint = if f.interferers.is_empty() && f.proxy.is_none() {
            String::new()
        } else {
            tr(
                " Если что-то всё же не открывается в браузере — посмотрите предупреждения ниже.",
                " If something still doesn't open in the browser, see the warnings below.",
            )
            .into()
        };
        return done(
            steps,
            Tone::Ok,
            tr("zapret работает", "zapret works"),
            trf!(
                "Discord и YouTube открываются ({} из {}).{hint}",
                "Discord and YouTube open ({} of {}).{hint}",
                check.passed,
                check.max
            ),
            None,
        );
    }

    if f.needs_timestamps && (!f.timestamps_allowed || f.timestamps_enabled == Some(false)) {
        step(
            &mut steps,
            "TCP timestamps",
            StepState::Fail,
            tr(
                "Выключены, а стратегия их требует",
                "Off, but the strategy needs them",
            ),
        );
        return done(
            steps,
            Tone::Error,
            tr("Стратегии не хватает TCP timestamps", "The strategy needs TCP timestamps"),
            trf!(
                "Стратегия «{title}» работает только с TCP timestamps. Разрешите KVT включать их — так делает и Flowseal.",
                "Strategy “{title}” only works with TCP timestamps. Allow KVT to turn them on — Flowseal does the same."
            ),
            Some(ZapretFix::AllowTimestamps),
        );
    }
    if let Some(name) = f.interferers.first() {
        return done(
            steps,
            Tone::Error,
            tr(
                "zapret мешает другая программа",
                "Another app interferes with zapret",
            ),
            trf!(
                "{name}. Если после этого не заработает — подберите стратегию.",
                "{name}. If it still doesn't work after that, pick a strategy."
            ),
            Some(ZapretFix::Autoselect),
        );
    }
    done(
        steps,
        Tone::Error,
        tr("Стратегия не помогает в этой сети", "The strategy doesn't help on this network"),
        trf!(
            "С «{title}» открывается {} из {} проверок. Провайдеры блокируют по-разному — подберите стратегию. Если не поможет ни одна, переустановите zapret.",
            "With “{title}”, {} of {} checks open. ISPs block in different ways — pick a strategy. If none helps, reinstall zapret.",
            check.passed,
            check.max
        ),
        Some(ZapretFix::Autoselect),
    )
}

#[tauri::command]
pub async fn zapret_diagnose(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ZapretDiagnosis, String> {
    Ok(diagnose(&app, &state).await?)
}

async fn diagnose(app: &AppHandle, state: &AppState) -> Result<ZapretDiagnosis, ZapretError> {
    let service = query_status().await.ok().flatten();
    let mut facts = ZapretFacts {
        service: service.clone(),
        ..Default::default()
    };
    if service.is_some() {
        facts.info = info().await.ok();
        facts.conflicts = conflicts(Request::ZapretConflicts)
            .await
            .unwrap_or_default();
        facts.running = running_strategy(state).await;
        let choice = state
            .choice
            .lock()
            .map_err(|_| ZapretError::State)?
            .zapret
            .clone();
        facts.timestamps_allowed = choice.tcp_timestamps;
        if let Some(running) = &facts.running {
            facts.needs_timestamps = strategies()
                .await
                .unwrap_or_default()
                .iter()
                .any(|s| &s.id == running && s.needs_timestamps);
        }
        let (interferers, proxy, timestamps) = tokio::task::spawn_blocking(move || {
            (interferers(), system_proxy(), tcp_timestamps_enabled())
        })
        .await
        .map_err(|_| ZapretError::State)?;
        facts.interferers = interferers;
        facts.proxy = proxy;
        facts.timestamps_enabled = timestamps;
        if facts.running.is_some() && facts.conflicts.is_empty() {
            facts.check = Some(check_now(app).await.check);
        }
    }
    Ok(conclude(&facts))
}
