//! Проверка zapret: цели Flowseal (Discord, YouTube) по TLS 1.2 и 1.3 и загрузка
//! больше 32 КБ, чтобы поймать заморозку после первых 16–20 КБ.

use super::*;

// ── Проверка ──

pub(super) fn client(tls12: bool) -> reqwest::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(4))
        // Каждая проверка — новое соединение: иначе проверялась бы прошлая стратегия.
        .pool_max_idle_per_host(0);
    if tls12 {
        b = b.max_tls_version(reqwest::tls::Version::TLS_1_2);
    }
    b.build()
}

/// Ответ пришёл (любой код HTTP) — значит, рукопожатие и запрос прошли DPI.
pub(super) async fn reachable(client: &reqwest::Client, url: &str) -> Option<u64> {
    let start = Instant::now();
    let result = client.get(url).send().await;
    log_check(url, result.is_ok(), start, "");
    result.ok().map(|_| start.elapsed().as_millis() as u64)
}

pub(super) fn log_check(url: &str, ok: bool, start: Instant, detail: &str) {
    use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
    let outcome = if ok { Outcome::Ok } else { Outcome::Failed };
    netlog::record(
        netlog::Event::new(
            Origin::App,
            Purpose::Zapret,
            &netlog::host_of(url),
            Route::Direct,
            outcome,
        )
        .ms(start.elapsed())
        .detail(detail),
    );
}

/// Загрузка проходит дальше окна заморозки (16–20 КБ).
pub(super) async fn downloads(client: &reqwest::Client) -> bool {
    let start = Instant::now();
    let ok = download_passes(client).await;
    let detail = if ok {
        kvt_core::i18n::tr("загрузка прошла", "download passed")
    } else {
        kvt_core::i18n::tr("загрузка оборвалась", "download dropped")
    };
    log_check(DOWNLOAD, ok, start, detail);
    ok
}

pub(super) async fn download_passes(client: &reqwest::Client) -> bool {
    let Ok(mut response) = client.get(DOWNLOAD).send().await else {
        return false;
    };
    let mut bytes = 0u64;
    loop {
        match tokio::time::timeout(STALL, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                bytes += chunk.len() as u64;
                if bytes >= DOWNLOAD_ENOUGH {
                    return true;
                }
            }
            // Файл кончился раньше порога — значит, не обрывали.
            Ok(Ok(None)) => return bytes > 0,
            _ => return false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetCheck {
    pub name: &'static str,
    /// Задержка по TLS 1.3 и TLS 1.2; `None` — не открылось.
    pub tls13: Option<u64>,
    pub tls12: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub targets: Vec<TargetCheck>,
    /// Загрузка больше 32 КБ прошла без обрыва.
    pub download: bool,
    pub passed: u32,
    pub max: u32,
    /// Суммарная задержка успешных проверок — для выбора между равными.
    pub latency_ms: u64,
}

impl Check {
    pub(super) fn better_than(&self, other: &Check) -> bool {
        (self.passed, std::cmp::Reverse(self.latency_ms))
            > (other.passed, std::cmp::Reverse(other.latency_ms))
    }

    pub fn healthy(&self) -> bool {
        self.passed + TOLERANCE >= self.max
    }
}

/// Все проверки параллельно: около 6 секунд.
pub async fn measure() -> Check {
    let (Ok(modern), Ok(tls12)) = (client(false), client(true)) else {
        return Check {
            targets: Vec::new(),
            download: false,
            passed: 0,
            max: MAX_SCORE,
            latency_ms: 0,
        };
    };
    let mut set = tokio::task::JoinSet::new();
    for (i, (_, _, url)) in TARGETS.iter().enumerate() {
        for (legacy, c) in [(false, modern.clone()), (true, tls12.clone())] {
            set.spawn(async move { (i, legacy, reachable(&c, url).await) });
        }
    }
    let download = tokio::spawn(async move { downloads(&modern).await });
    let mut targets: Vec<TargetCheck> = TARGETS
        .iter()
        .map(|(ru, en, _)| TargetCheck {
            name: kvt_core::i18n::tr(ru, en),
            tls13: None,
            tls12: None,
        })
        .collect();
    while let Some(Ok((i, legacy, ms))) = set.join_next().await {
        if legacy {
            targets[i].tls12 = ms;
        } else {
            targets[i].tls13 = ms;
        }
    }
    let download = download.await.unwrap_or(false);
    let ok: Vec<u64> = targets
        .iter()
        .flat_map(|t| [t.tls13, t.tls12])
        .flatten()
        .collect();
    Check {
        passed: ok.len() as u32 + u32::from(download),
        latency_ms: ok.iter().sum(),
        targets,
        download,
        max: MAX_SCORE,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRecord {
    /// Unix-время проверки.
    pub at: u64,
    /// Стратегия во время проверки; `None` — zapret не работал.
    pub strategy: Option<String>,
    pub check: Check,
}

/// Стратегия, которая работает сейчас (в режиме «Zapret» или в гибриде).
pub(super) async fn running_strategy(state: &AppState) -> Option<String> {
    match query_status().await.ok().flatten()? {
        ServiceStatus::Zapret { strategy } => Some(strategy),
        ServiceStatus::Connected { .. } => {
            let choice = state.choice.lock().ok()?.clone();
            (choice.mode.as_deref() == Some("hybrid"))
                .then(|| choice.zapret.strategy_for(network_key(state).as_deref()))
        }
        _ => None,
    }
}

pub(super) async fn check_now(app: &AppHandle) -> CheckRecord {
    let state = app.state::<AppState>();
    let strategy = running_strategy(&state).await;
    let record = CheckRecord {
        at: now_unix(),
        strategy,
        check: measure().await,
    };
    if let Ok(mut last) = state.zapret_last.lock() {
        *last = Some(record.clone());
    }
    let _ = app.emit(CHECK_EVENT, &record);
    record
}

/// «Проверить сейчас»: открываются ли Discord и YouTube с текущими настройками.
#[tauri::command]
pub async fn zapret_check(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CheckRecord, String> {
    if state.zapret_picking.load(Ordering::SeqCst) {
        return Err(tr("Идёт подбор стратегии", "A strategy is being picked").into());
    }
    Ok(check_now(&app).await)
}

#[tauri::command]
pub fn zapret_last(state: State<'_, AppState>) -> Option<CheckRecord> {
    state.zapret_last.lock().ok().and_then(|l| l.clone())
}
