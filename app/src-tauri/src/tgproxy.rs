//! Прокси для Telegram Desktop рядом с zapret: работает в режимах «Zapret» и
//! «Гибрид», пока включён в настройках zapret.
//!
//! Прокси запускает окно (KVT в трее), а не служба: прав ему не нужно, и чужой
//! сетевой код не должен работать от SYSTEM. Процесс живёт в Job Object с
//! `KILL_ON_JOB_CLOSE` — закрылся KVT, закрылся и прокси. Перед каждым запуском
//! сверяется SHA-256 исполняемого файла. Слушает только `127.0.0.1`.
//!
//! Состояние сверяется с режимом при каждом обновлении трея (раз в 5 секунд и
//! после действий пользователя): нужен — запущен, не нужен — остановлен.

#![allow(unsafe_code)]

use crate::{query_status, AppState};
use kvt_core::ipc::ServiceStatus;
use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::tgproxy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use tauri::{AppHandle, Manager};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// tg-ws-proxy-rs 2.7.0 (`scripts/fetch-tgproxy.ps1`).
const EXE_SHA256: &str = "18917ecd9dcaeeec510483b90fbc7bc20c171838c6edfbc8d667e48a6801afad";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Список доменов Cloudflare обновляется не чаще, чем раз в столько.
const DOMAINS_TTL: Duration = Duration::from_secs(6 * 3600);
/// После неудачного запуска — пауза, чтобы не перезапускать прокси каждые 5 секунд.
const RETRY_AFTER: Duration = Duration::from_secs(60);
const SECRET_FILE: &str = "tgproxy.key";
const DOMAINS_FILE: &str = "tgproxy-domains.txt";

/// Job Object «убить при закрытии»: прокси не переживает KVT, даже аварийный выход.
struct Job(HANDLE);

// SAFETY: handle job-объекта можно использовать из любого потока.
unsafe impl Send for Job {}

impl Job {
    fn kill_on_close() -> std::io::Result<Self> {
        // SAFETY: без атрибутов и имени — анонимный job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Job(handle);
        // SAFETY: структура из простых полей, нули — допустимое значение.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: указатель и точный размер структуры нужного класса.
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign(&self, process: HANDLE) -> std::io::Result<()> {
        // SAFETY: оба handle валидны на время вызова.
        if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: handle создан в kill_on_close и закрывается один раз;
        // закрытие последнего handle завершает процессы job-объекта.
        unsafe { CloseHandle(self.0) };
    }
}

struct Running {
    child: tokio::process::Child,
    _job: Job,
    started: Instant,
}

#[derive(Default)]
struct Inner {
    running: Option<Running>,
    /// Последняя ошибка запуска и когда она была.
    error: Option<(Instant, String)>,
}

static INNER: tokio::sync::Mutex<Option<Inner>> = tokio::sync::Mutex::const_new(None);

/// Домены Cloudflare: последние известные (из файла или сети) и когда обновлены.
static DOMAINS: Mutex<Option<(Vec<String>, Option<SystemTime>)>> = Mutex::new(None);
static FETCHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Домены Cloudflare для медиа: последние известные, иначе запасной список.
pub fn domains() -> Vec<String> {
    let guard = DOMAINS.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some((list, _)) if !list.is_empty() => list.clone(),
        _ => tgproxy::fallback_domains(),
    }
}

/// Имена, которые winws не трогает, когда прокси включён.
pub fn zapret_exclusions() -> Vec<String> {
    tgproxy::zapret_exclusions(&domains())
}

/// Правила для соединений прокси, пока работает VPN (см. `tgproxy::route_rules`).
pub fn route_rules(hybrid: bool, route: tgproxy::Route) -> Vec<kvt_core::routing::Rule> {
    tgproxy::route_rules(&domains(), hybrid, route)
}

fn exe_path() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .join("tgproxy")
            .join("tg-ws-proxy.exe"),
    )
}

fn verify(exe: &Path) -> Result<(), String> {
    let bytes = std::fs::read(exe).map_err(|_| {
        kvt_core::i18n::tr(
            "Не найден прокси для Telegram. Переустановите KVT (для разработки: scripts\\fetch-tgproxy.ps1).",
            "The Telegram proxy wasn't found. Reinstall KVT (for development: scripts\\fetch-tgproxy.ps1).",
        )
        .to_owned()
    })?;
    let hash: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if hash != EXE_SHA256 {
        return Err(kvt_core::i18n::tr(
            "Файл прокси для Telegram изменён — KVT его не запустит. Переустановите KVT.",
            "The Telegram proxy file was modified — KVT won't run it. Reinstall KVT.",
        )
        .into());
    }
    Ok(())
}

/// 16 случайных байт из системного генератора Windows.
fn random_secret() -> Result<String, String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut buf = [0u8; 16];
    // SAFETY: буфер на стеке нужного размера; алгоритм — системный по умолчанию.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(kvt_core::i18n::tr(
            "Не удалось создать ключ прокси для Telegram.",
            "Couldn't create the Telegram proxy key.",
        )
        .into());
    }
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Секрет прокси: создаётся один раз и хранится под DPAPI (только этот пользователь
/// Windows). Telegram запоминает его вместе с адресом прокси, поэтому он не меняется.
fn secret(app: &AppHandle) -> Result<String, String> {
    let dir = app.path().app_config_dir().map_err(|_| {
        kvt_core::i18n::tr(
            "Не найдена папка настроек Windows.",
            "The Windows settings folder wasn't found.",
        )
        .to_owned()
    })?;
    // Запуск прокси и «Открыть в Telegram» при первом включении приходят почти разом:
    // без блокировки каждый создал бы свой секрет, и Telegram получил бы не тот, с
    // которым запущен прокси.
    static CREATE: Mutex<()> = Mutex::new(());
    let _creating = CREATE.lock().unwrap_or_else(|e| e.into_inner());
    let path = dir.join(SECRET_FILE);
    if let Some(s) = std::fs::read(&path)
        .ok()
        .and_then(|c| crate::dpapi::unprotect(&c).ok())
        .and_then(|p| String::from_utf8(p).ok())
        .filter(|s| tgproxy::valid_secret(s))
    {
        return Ok(s);
    }
    let s = random_secret()?;
    let sealed = crate::dpapi::protect(s.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Целиком или никак: оборванная запись дала бы новый секрет при следующем
    // запуске, и Telegram пришлось бы настраивать заново.
    crate::atomic::write(&path, &dir.join(format!("{SECRET_FILE}.tmp")), &sealed)
        .map_err(|e| e.to_string())?;
    Ok(s)
}

fn data_dir(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_data_dir().ok()
}

/// Читает сохранённый список доменов при первом обращении.
fn load_domains(app: &AppHandle) {
    let mut guard = DOMAINS.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return;
    }
    let path = data_dir(app).map(|d| d.join(DOMAINS_FILE));
    let saved = path.as_ref().and_then(|p| {
        let text = std::fs::read_to_string(p).ok()?;
        let at = std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let list: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|d| kvt_core::zapret::valid_domain(d))
            .map(str::to_owned)
            .collect();
        Some((list, at))
    });
    *guard = Some(saved.unwrap_or_default());
}

fn domains_stale() -> bool {
    let guard = DOMAINS.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some((list, Some(at))) if !list.is_empty() => {
            at.elapsed().map_or(true, |age| age > DOMAINS_TTL)
        }
        _ => true,
    }
}

/// Свежий список доменов у Flowseal — в фоне, не чаще раза в 6 часов. Виден в «Журнале».
fn refresh_domains(app: &AppHandle) {
    if !domains_stale() || FETCHING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let result = fetch_domains().await;
        let now = SystemTime::now();
        let mut guard = DOMAINS.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(list) => {
                if let Some(dir) = data_dir(&app) {
                    let _ = std::fs::create_dir_all(&dir);
                    let _ = std::fs::write(dir.join(DOMAINS_FILE), list.join("\n"));
                }
                *guard = Some((list, Some(now)));
            }
            // Не вышло — повтор через те же 6 часов, а пока прежний или запасной список.
            Err(_) => {
                let list = guard.take().map(|(l, _)| l).unwrap_or_default();
                *guard = Some((list, Some(now)));
            }
        }
        FETCHING.store(false, std::sync::atomic::Ordering::SeqCst);
    });
}

async fn fetch_domains() -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("KVT/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    let body = async {
        let resp = client
            .get(tgproxy::DOMAINS_URL)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !resp.status().is_success() {
            return Err(kvt_core::trf!(
                "GitHub ответил ошибкой {}",
                "GitHub returned error {}",
                resp.status().as_u16()
            ));
        }
        // Список — пара десятков строк; больше 64 КБ — не он.
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err(kvt_core::i18n::tr("слишком большой ответ", "response too large").into());
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
    .await;
    let list = body.as_ref().map(|t| tgproxy::parse_domains(t));
    let ok = list.as_ref().is_ok_and(|l| !l.is_empty());
    netlog::record(
        netlog::Event::new(
            Origin::App,
            Purpose::Zapret,
            &netlog::host_of(tgproxy::DOMAINS_URL),
            Route::Direct,
            if ok { Outcome::Ok } else { Outcome::Failed },
        )
        .ms(start.elapsed())
        .detail(body.as_ref().err().map_or(
            kvt_core::i18n::tr(
                "домены медиа для прокси Telegram",
                "media domains for the Telegram proxy",
            ),
            String::as_str,
        )),
    );
    match list {
        Ok(l) if !l.is_empty() => Ok(l),
        Ok(_) => Err(kvt_core::i18n::tr("пустой список", "empty list").into()),
        Err(e) => Err(e.clone()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    /// Запустить, если не работает.
    Run,
    /// Не трогать: идёт подключение или переподключение, служба не ответила.
    Keep,
    Stop,
}

/// Нужен ли прокси сейчас. Работает, пока включён и KVT подключён в любом режиме: в
/// «VPN» прокси ходит через VPN — Telegram, однажды настроенный на прокси, не должен
/// отваливаться при смене режима.
///
/// Переходные состояния прокси не трогают. Раньше он гас на каждом «Подключение…» и
/// поднимался снова — разом рвались все соединения Telegram, ядро писало про каждый
/// обрыв, и это раскачивало переподключения VPN по кругу.
fn want(enabled: bool, status: Option<&ServiceStatus>) -> Want {
    if !enabled {
        return Want::Stop;
    }
    match status {
        Some(ServiceStatus::Zapret { .. } | ServiceStatus::Connected { .. }) => Want::Run,
        Some(ServiceStatus::Disconnected) | Some(ServiceStatus::Failed { blocked: false, .. }) => {
            Want::Stop
        }
        // Подключение, kill switch держит после сбоя, служба не ответила.
        Some(ServiceStatus::Connecting)
        | Some(ServiceStatus::Failed { blocked: true, .. })
        | None => Want::Keep,
    }
}

/// Порт уже занят: обычно это другой прокси для Telegram (tg-ws-proxy Flowseal в трее
/// или сборка внутри другой программы). Запускать второй бессмысленно — он не встанет.
fn port_busy() -> bool {
    std::net::TcpListener::bind(("127.0.0.1", tgproxy::PORT)).is_err()
}

/// Журнал прокси — последние строки, без секрета (для экспорта диагностики).
pub fn log_tail() -> String {
    let Some(path) = LOG_PATH.lock().ok().and_then(|p| p.clone()) else {
        return String::new();
    };
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(300);
    lines[start..]
        .iter()
        .map(|l| mask_secret(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Прокси печатает секрет при запуске (строка `Secret:` и ссылка `secret=dd…`).
fn mask_secret(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        // 32 и больше шестнадцатеричных символов подряд — секрет (с `dd`/`ee` или без).
        if run.len() >= 32 {
            out.push_str("<скрыто>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in line.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Если прокси завершился так быстро — это не сбой в работе, а ошибка запуска
/// (порт, антивирус): перезапускать каждые 5 секунд бессмысленно.
const EARLY_EXIT: Duration = Duration::from_secs(15);

async fn start(app: &AppHandle) -> Result<Running, String> {
    let exe = exe_path().ok_or(kvt_core::i18n::tr(
        "Не найден каталог программы.",
        "The app folder wasn't found.",
    ))?;
    verify(&exe)?;
    if port_busy() {
        return Err(kvt_core::trf!(
            "Порт {} занят другой программой — скорее всего, уже запущен другой прокси для Telegram (например, tg-ws-proxy Flowseal). Закройте его: адрес у прокси KVT тот же, Telegram перенастраивать не нужно.",
            "Port {} is taken by another app — most likely another Telegram proxy is running (e.g. Flowseal's tg-ws-proxy). Close it: KVT's proxy has the same address, so Telegram needs no reconfiguring.",
            tgproxy::PORT
        ));
    }
    let secret = secret(app)?;
    let log = data_dir(app)
        .map(|d| d.join("logs"))
        .inspect(|d| {
            let _ = std::fs::create_dir_all(d);
        })
        .map(|d| d.join("tgproxy.log"))
        .ok_or(kvt_core::i18n::tr(
            "Не найдена папка данных.",
            "The data folder wasn't found.",
        ))?;
    // Прокси дописывает журнал без ограничений — при запуске больше 1 МБ не держим.
    if std::fs::metadata(&log).is_ok_and(|m| m.len() > 1024 * 1024) {
        let old = log.with_extension("log.1");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&log, old);
    }
    if let Ok(mut p) = LOG_PATH.lock() {
        *p = Some(log.clone());
    }
    let domains = domains();
    let args = tgproxy::args(&domains, &log.to_string_lossy());
    let mut cmd = tokio::process::Command::new(&exe);
    for (key, _) in std::env::vars_os() {
        let inherited = key.to_str().is_some_and(|k| {
            k.get(..tgproxy::ENV_PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(tgproxy::ENV_PREFIX))
        });
        if inherited {
            cmd.env_remove(&key);
        }
    }
    let child = cmd
        .env(tgproxy::SECRET_ENV, &secret)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            kvt_core::trf!(
                "Прокси для Telegram не запустился: {e}",
                "The Telegram proxy didn't start: {e}"
            )
        })?;
    let job = Job::kill_on_close().map_err(|e| e.to_string())?;
    if let Some(handle) = child.raw_handle() {
        job.assign(handle as HANDLE).map_err(|e| e.to_string())?;
    }
    tracing::info!("прокси Telegram запущен");
    Ok(Running {
        child,
        _job: job,
        started: Instant::now(),
    })
}

async fn stop(inner: &mut Inner) {
    if let Some(mut r) = inner.running.take() {
        let _ = r.child.kill().await;
        tracing::info!("прокси Telegram остановлен");
    }
}

/// Приводит прокси в соответствие с режимом. Повторный вызов, пока идёт прежний,
/// пропускается: следующий придёт через 5 секунд.
pub async fn sync(app: &AppHandle, status: Option<&ServiceStatus>) {
    let Ok(mut guard) = INNER.try_lock() else {
        return;
    };
    let inner = guard.get_or_insert_with(Inner::default);
    let enabled = app
        .state::<AppState>()
        .choice
        .lock()
        .map(|c| c.zapret.telegram)
        .unwrap_or(false);
    match want(enabled, status) {
        Want::Stop => {
            stop(inner).await;
            inner.error = None;
            return;
        }
        Want::Keep => return,
        Want::Run => {}
    }
    load_domains(app);
    refresh_domains(app);
    // Упал сам — перезапуск. Новый список доменов Cloudflare работающий прокси не
    // перезапускает (это оборвало бы Telegram): список вступит в силу со следующим
    // запуском, а пока прокси обходится прежним.
    if let Some(r) = inner.running.as_mut() {
        let alive = matches!(r.child.try_wait(), Ok(None));
        if alive {
            return;
        }
        let early = !alive && r.started.elapsed() < EARLY_EXIT;
        if early {
            tracing::warn!("прокси Telegram завершился сразу после запуска");
        } else if !alive {
            tracing::warn!("прокси Telegram завершился — перезапуск");
        }
        stop(inner).await;
        if early {
            // Повтор через минуту, а не каждые 5 секунд.
            inner.error = Some((
                Instant::now(),
                kvt_core::i18n::tr("Прокси для Telegram завершился сразу после запуска. Возможно, его остановил антивирус — добавьте папку KVT в исключения. Подробности — в экспорте диагностики (tgproxy.log).", "The Telegram proxy exited right after starting. Antivirus may have stopped it — add the KVT folder to exclusions. Details are in the diagnostics export (tgproxy.log).").into(),
            ));
        }
    }
    if inner
        .error
        .as_ref()
        .is_some_and(|(at, _)| at.elapsed() < RETRY_AFTER)
    {
        return;
    }
    match start(app).await {
        Ok(r) => {
            inner.running = Some(r);
            inner.error = None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "прокси Telegram не запущен");
            inner.error = Some((Instant::now(), e));
        }
    }
}

/// Сверить состояние сразу, не дожидаясь трея (после смены настроек).
pub fn kick(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let status = query_status().await.ok().flatten();
        sync(&app, status.as_ref()).await;
    });
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TgProxyStatus {
    /// Прокси сейчас работает.
    running: bool,
    /// Почему не запустился (если пытались).
    error: Option<String>,
    port: u16,
}

#[tauri::command]
pub async fn tg_proxy_status() -> TgProxyStatus {
    let mut guard = INNER.lock().await;
    let inner = guard.get_or_insert_with(Inner::default);
    let running = inner
        .running
        .as_mut()
        .is_some_and(|r| matches!(r.child.try_wait(), Ok(None)));
    TgProxyStatus {
        running,
        error: inner.error.as_ref().map(|(_, e)| e.clone()),
        port: tgproxy::PORT,
    }
}

/// Открывает в Telegram окно «Подключить прокси» (ссылка `tg://proxy`).
#[tauri::command]
pub fn tg_proxy_open(app: AppHandle) -> Result<(), String> {
    let link = tgproxy::link(&secret(&app)?);
    crate::about::shell_open(&link).map_err(|_| {
        kvt_core::i18n::tr(
            "Не удалось открыть Telegram — установите Telegram Desktop или скопируйте ссылку.",
            "Couldn't open Telegram — install Telegram Desktop or copy the link.",
        )
        .into()
    })
}

/// Ссылка для ручного подключения (если Telegram не открылся сам).
#[tauri::command]
pub fn tg_proxy_link(app: AppHandle) -> Result<String, String> {
    Ok(tgproxy::link(&secret(&app)?))
}

#[cfg(test)]
mod tests {
    use super::{mask_secret, want, Want};
    use kvt_core::core_select::CoreKind;
    use kvt_core::ipc::ServiceStatus;

    #[test]
    fn transitions_do_not_restart_the_proxy() {
        let connected = ServiceStatus::Connected {
            core: CoreKind::Xray,
        };
        assert_eq!(want(true, Some(&connected)), Want::Run);
        assert_eq!(
            want(
                true,
                Some(&ServiceStatus::Zapret {
                    strategy: "g".into()
                })
            ),
            Want::Run
        );
        assert_eq!(want(true, Some(&ServiceStatus::Connecting)), Want::Keep);
        assert_eq!(want(true, None), Want::Keep);
        let blocked = ServiceStatus::Failed {
            reason: String::new(),
            blocked: true,
        };
        assert_eq!(want(true, Some(&blocked)), Want::Keep);
        assert_eq!(want(true, Some(&ServiceStatus::Disconnected)), Want::Stop);
        assert_eq!(want(false, Some(&connected)), Want::Stop);
    }

    #[test]
    fn secret_never_reaches_diagnostics() {
        let s = "00112233445566778899aabbccddeeff";
        assert_eq!(
            mask_secret(&format!("  Secret:        {s}")),
            "  Secret:        <скрыто>"
        );
        assert_eq!(
            mask_secret(&format!(
                "tg://proxy?server=127.0.0.1&port=1443&secret=dd{s}"
            )),
            "tg://proxy?server=127.0.0.1&port=1443&secret=<скрыто>"
        );
        let plain = "[127.0.0.1:61876] DC203 → CF proxy pool hit (kws203.pclead.co.uk)";
        assert_eq!(mask_secret(plain), plain);
    }
}
