//! Сообщение о новой версии KVT. Через пару минут после запуска и затем раз в
//! 12 часов KVT спрашивает у GitHub номер последнего релиза. Если он новее
//! установленного — сообщение в окне (а при закрытом окне — уведомление Windows) со
//! ссылкой на страницу релиза. Скачивает и ставит обновление пользователь сам: KVT
//! ничего не загружает и не запускает (решение 5.7 остаётся в силе).
//!
//! Запрос один — `releases/latest` к api.github.com, без идентификаторов, виден в
//! «Журнале». Выключается в «Настройках» → «О программе».

use crate::{notify, AppState};
use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::zapret::{newer, valid_version};
use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};

const API: &str = "https://api.github.com/repos/kostiashkaaa/KVT-client/releases/latest";
const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// Первая проверка — не сразу: при запуске с Windows сеть ещё поднимается.
const FIRST_DELAY: Duration = Duration::from_secs(2 * 60);
const INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
/// Кнопка «Проверить» после удачной проверки чаще раза в минуту в сеть не ходит.
const MANUAL_GAP: Duration = Duration::from_secs(60);
/// Окно перечитывает `update_status`.
pub const EVENT: &str = "update-available";

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    current: &'static str,
    /// Последняя версия на GitHub; `None` — ещё не проверяли или проверка не удалась.
    latest: Option<String>,
    /// Последняя версия новее установленной.
    available: bool,
    /// Когда проверяли (Unix-время, мс).
    checked_at: Option<u64>,
    error: Option<String>,
}

#[derive(Default)]
struct Cache {
    status: UpdateStatus,
    at: Option<Instant>,
    /// О какой версии уже сообщили уведомлением Windows — второй раз не надо.
    notified: Option<String>,
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

fn with_cache<T>(f: impl FnOnce(&mut Cache) -> T) -> T {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(Cache::default))
}

fn enabled(app: &AppHandle) -> bool {
    app.state::<AppState>()
        .choice
        .lock()
        .map(|c| c.check_updates)
        .unwrap_or(true)
}

/// Номер версии из ответа `releases/latest` (тег `v0.9.1`).
fn parse_latest(body: &[u8]) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct Raw {
        tag_name: String,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|_| {
        kvt_core::i18n::tr(
            "GitHub ответил непонятно",
            "GitHub sent an unexpected answer",
        )
    })?;
    let version = raw.tag_name.trim_start_matches('v');
    if valid_version(version) {
        Ok(version.to_owned())
    } else {
        Err(kvt_core::i18n::tr(
            "GitHub ответил непонятно",
            "GitHub sent an unexpected answer",
        )
        .into())
    }
}

async fn fetch_latest() -> Result<String, String> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("KVT/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(describe)?;
    let start = Instant::now();
    let body = async {
        let resp = client
            .get(API)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(describe)?;
        if !resp.status().is_success() {
            return Err(kvt_core::trf!(
                "GitHub ответил ошибкой {}",
                "GitHub returned error {}",
                resp.status().as_u16()
            ));
        }
        resp.bytes().await.map_err(describe)
    }
    .await;
    netlog::record(
        netlog::Event::new(
            Origin::App,
            Purpose::Update,
            &netlog::host_of(API),
            Route::Direct,
            if body.is_ok() {
                Outcome::Ok
            } else {
                Outcome::Failed
            },
        )
        .ms(start.elapsed())
        .detail(body.as_ref().err().map_or(
            kvt_core::i18n::tr("версия KVT", "KVT version"),
            String::as_str,
        )),
    );
    parse_latest(&body?)
}

/// Ошибка запроса — по-русски, без адреса (он и так известен).
fn describe(e: reqwest::Error) -> String {
    use kvt_core::i18n::tr;
    if e.is_timeout() {
        tr("GitHub не ответил вовремя", "GitHub didn't respond in time").into()
    } else if e.is_connect() {
        tr("нет связи с GitHub", "can't reach GitHub").into()
    } else {
        tr("запрос к GitHub не прошёл", "the GitHub request failed").into()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

async fn check(app: &AppHandle) -> UpdateStatus {
    let result = fetch_latest().await;
    let status = UpdateStatus {
        current: CURRENT,
        available: result.as_ref().is_ok_and(|v| newer(v, CURRENT)),
        latest: result.as_ref().ok().cloned(),
        checked_at: Some(now_ms()),
        error: result.err(),
    };
    let fresh = with_cache(|c| {
        c.status = status.clone();
        // После ошибки «Проверить сейчас» повторяет сразу, а не через минуту.
        c.at = status.error.is_none().then(Instant::now);
        let fresh = status.available && c.notified != status.latest;
        if fresh {
            c.notified = status.latest.clone();
        }
        fresh
    });
    if fresh {
        let _ = app.emit(EVENT, ());
        let version = status.latest.as_deref().unwrap_or_default();
        notify::show(
            app,
            notify::Notice {
                title: kvt_core::trf!("Вышла KVT {version}", "KVT {version} is out"),
                body: kvt_core::i18n::tr(
                    "Скачайте её на странице загрузки — настройки и подписки сохранятся.",
                    "Download it from the download page — your settings and subscriptions will be kept.",
                )
                .into(),
                page: Some("settings".into()),
                force: false,
            },
        );
    }
    status
}

pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_DELAY).await;
        loop {
            if enabled(&app) {
                check(&app).await;
            }
            tokio::time::sleep(INTERVAL).await;
        }
    });
}

/// Что известно о новой версии (без запроса в сеть).
#[tauri::command]
pub fn update_status() -> UpdateStatus {
    with_cache(|c| UpdateStatus {
        current: CURRENT,
        ..c.status.clone()
    })
}

/// Проверить сейчас (кнопка в «О программе»): работает и при выключенной проверке.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> UpdateStatus {
    let recent = with_cache(|c| c.at.is_some_and(|at| at.elapsed() < MANUAL_GAP));
    if recent {
        return update_status();
    }
    check(&app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_becomes_version() {
        assert_eq!(
            parse_latest(br#"{"tag_name":"v0.9.1","name":"KVT"}"#).unwrap(),
            "0.9.1"
        );
        assert!(parse_latest(br#"{"tag_name":"v1.0.0-rc.1"}"#).is_err());
        assert!(parse_latest(br#"{"tag_name":"<script>"}"#).is_err());
        assert!(parse_latest(b"not json").is_err());
    }

    #[test]
    fn newer_is_numeric() {
        assert!(newer("0.10.0", "0.9.1"));
        assert!(!newer("0.9.0", "0.9.1"));
        assert!(!newer("0.9.1", "0.9.1"));
    }
}
