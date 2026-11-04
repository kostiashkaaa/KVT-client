//! Загрузка подписки по ссылке. Ссылка — секрет (в ней токен), поэтому она не
//! попадает ни в тексты ошибок, ни в логи.

use kvt_core::governor::{Decision, NetGovernor};
use kvt_core::netlog::{self, Origin, Purpose, Route};
use kvt_core::subscription::{parse_headers, SubscriptionMeta, MAX_BODY_BYTES};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

pub struct Fetched {
    pub meta: SubscriptionMeta,
    pub body: String,
}

pub fn validate_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw.trim()).map_err(|_| "Ссылка на подписку повреждена".to_string())?;
    if url.scheme() != "https" {
        return Err("Подписка загружается только по https".into());
    }
    if url.host_str().is_none() {
        return Err("В ссылке нет адреса сервера".into());
    }
    Ok(url)
}

/// Проверка лимитов NetGovernor до сетевого запроса.
pub fn acquire(governor: &Mutex<NetGovernor>, host: &str) -> Result<(), String> {
    let now = Instant::now();
    let decision = governor
        .lock()
        .map_err(crate::errors::state)?
        .try_acquire(host, now);
    netlog::record_hold(
        Origin::App,
        Purpose::Subscription,
        host,
        Route::Direct,
        &decision,
    );
    match decision {
        Decision::Allowed => Ok(()),
        Decision::RetryAt(at) => Err(format!(
            "Слишком частые запросы к серверу подписки — повторите через {} с",
            at.saturating_duration_since(now).as_secs().max(1)
        )),
        Decision::Frozen { until } => Err(format!(
            "Провайдер интернета притормозил соединения с этим сервером — подождите {} с",
            until.saturating_duration_since(now).as_secs().max(1)
        )),
    }
}

pub async fn fetch(url: &Url) -> Result<Fetched, String> {
    let start = Instant::now();
    let result = fetch_inner(url).await;
    let outcome = if result.is_ok() {
        netlog::Outcome::Ok
    } else {
        netlog::Outcome::Failed
    };
    let mut event = netlog::Event::new(
        Origin::App,
        Purpose::Subscription,
        url.host_str().unwrap_or_default(),
        Route::Direct,
        outcome,
    )
    .ms(start.elapsed());
    if let Err(e) = &result {
        event = event.detail(e);
    }
    netlog::record(event);
    result
}

async fn fetch_inner(url: &Url) -> Result<Fetched, String> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("KVT/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(describe)?;

    let mut resp = client.get(url.clone()).send().await.map_err(describe)?;
    if !resp.status().is_success() {
        return Err(format!(
            "Сервер подписки ответил ошибкой {}",
            resp.status().as_u16()
        ));
    }
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
    {
        return Err("Подписка слишком большая".into());
    }

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    let meta = parse_headers(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(describe)? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err("Подписка слишком большая".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Fetched {
        meta,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Человеческое описание ошибки без URL (в нём токен подписки).
fn describe(e: reqwest::Error) -> String {
    let e = e.without_url();
    if e.is_timeout() {
        "Сервер подписки не ответил вовремя".into()
    } else if e.is_connect() {
        "Не удалось подключиться к серверу подписки — возможно, он заблокирован. Включите VPN и повторите".into()
    } else if e.is_redirect() {
        "Сервер подписки перенаправляет слишком много раз".into()
    } else {
        format!("Не удалось загрузить подписку: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::governor::NetPolicy;

    #[test]
    fn only_https_is_accepted() {
        assert!(validate_url("https://sub.example.com/abc").is_ok());
        assert!(validate_url("http://sub.example.com/abc").is_err());
        assert!(validate_url("vless://x@y:1").is_err());
    }

    #[test]
    fn errors_do_not_contain_token() {
        let err = validate_url("http://sub.example.com/SECRET-TOKEN").unwrap_err();
        assert!(!err.contains("SECRET"));
    }

    #[test]
    fn second_immediate_fetch_is_throttled() {
        let g = Mutex::new(NetGovernor::new(NetPolicy::default()));
        assert!(acquire(&g, "sub.example.com").is_ok());
        assert!(acquire(&g, "sub.example.com")
            .unwrap_err()
            .contains("повторите"));
    }
}
