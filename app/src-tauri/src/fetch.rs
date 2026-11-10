//! Загрузка подписки по ссылке. Ссылка — секрет (в ней токен), поэтому она не
//! попадает ни в тексты ошибок, ни в логи.

use kvt_core::governor::{Decision, NetGovernor};
use kvt_core::netlog::{self, Origin, Purpose, Route};
use kvt_core::parser::parse_subscription_body;
use kvt_core::subscription::{parse_headers, SubscriptionMeta, MAX_BODY_BYTES};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

pub struct Fetched {
    pub meta: SubscriptionMeta,
    pub body: String,
}

pub fn validate_url(raw: &str) -> Result<Url, String> {
    // Ссылки «добавить в Happ / INCY / v2RayTun …» — в исходный адрес подписки.
    let unwrapped = kvt_core::subscription::unwrap_app_link(raw).map_err(str::to_owned)?;
    let raw = unwrapped.as_deref().unwrap_or(raw);
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
    settle(host, decision, now)
}

/// Как `acquire`, но паузу до `max_wait` выжидает, а не отказывает: несколько подписок
/// одного провайдера (один адрес) обновляются подряд, а не «слишком частыми запросами».
/// Заморозку не выжидаем — это признак ТСПУ, о нём надо сказать сразу.
pub async fn acquire_patiently(
    governor: &Mutex<NetGovernor>,
    host: &str,
    max_wait: Duration,
) -> Result<(), String> {
    // Часы tokio: в тестах время виртуальное и проходит без настоящего ожидания.
    let clock = || tokio::time::Instant::now().into_std();
    let deadline = clock() + max_wait;
    loop {
        let now = clock();
        let decision = governor
            .lock()
            .map_err(crate::errors::state)?
            .try_acquire(host, now);
        match decision {
            Decision::RetryAt(at) if at <= deadline => {
                tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
            }
            other => return settle(host, other, now),
        }
    }
}

fn settle(host: &str, decision: Decision, now: Instant) -> Result<(), String> {
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

/// Как KVT представляется серверу подписки. Панели провайдеров (Remnawave,
/// Marzban и др.) выбирают формат по User-Agent: незнакомому клиенту отвечают 404.
/// v2rayNG и Happ получают конфиги Xray в JSON — в них бывают серверы, которых нет в
/// списке ссылок (у провайдера из беты — все серверы Hysteria2); v2rayN 6 и Hiddify —
/// обычный список ссылок. Своё имя в строке остаётся — провайдер видит, кто пришёл.
/// Пробуем по очереди, пока в ответе не найдутся серверы.
fn user_agents() -> [String; 5] {
    let kvt = concat!("KVT/", env!("CARGO_PKG_VERSION"));
    [
        format!("v2rayNG/1.10.5 {kvt}"),
        format!("v2rayN/6.60 {kvt}"),
        format!("Hiddify/2.5.7 {kvt}"),
        // Часть провайдеров отдаёт серверы только «своему» клиенту Happ.
        format!("Happ/3.6.1 {kvt}"),
        kvt.to_owned(),
    ]
}

async fn fetch_inner(url: &Url) -> Result<Fetched, String> {
    let mut first_error = None;
    for agent in user_agents() {
        match fetch_as(url, &agent).await {
            Ok(fetched) if !parse_subscription_body(&fetched.body).servers.is_empty() => {
                return Ok(fetched)
            }
            // Ответ есть, но не в понятном KVT формате — пробуем следующего клиента.
            Ok(fetched) => {
                first_error.get_or_insert(Ok(fetched));
            }
            Err(e) => {
                first_error.get_or_insert(Err(e));
            }
        }
    }
    // Ни один вариант не дал серверов: вернуть первое, что было (ошибку или ответ —
    // тогда «не нашлось серверов» скажет проверка подписки).
    first_error.unwrap_or_else(|| Err("Не удалось загрузить подписку".into()))
}

async fn fetch_as(url: &Url, agent: &str) -> Result<Fetched, String> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(agent)
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
    fn known_clients_first_own_name_kept() {
        let agents = user_agents();
        assert!(agents[0].starts_with("v2rayNG/"));
        assert!(agents.iter().all(|a| a.contains("KVT/")));
    }

    /// Настоящая подписка: `KVT_SUB_URL=https://… cargo test -p kvt-app real_subscription -- --ignored`.
    #[tokio::test]
    #[ignore = "ходит в сеть по ссылке из KVT_SUB_URL"]
    async fn real_subscription() {
        let url = validate_url(&std::env::var("KVT_SUB_URL").unwrap()).unwrap();
        let fetched = fetch_inner(&url).await.unwrap();
        let n = parse_subscription_body(&fetched.body).servers.len();
        println!("серверов: {n}");
        assert!(n > 0);
    }

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

    #[tokio::test(start_paused = true)]
    async fn patient_acquire_waits_out_short_pause() {
        let g = Mutex::new(NetGovernor::new(NetPolicy::default()));
        assert!(acquire(&g, "sub.example.com").is_ok());
        // Пауза между запросами — 2 с: в пределах ожидания дожидаемся.
        assert!(
            acquire_patiently(&g, "sub.example.com", Duration::from_secs(5))
                .await
                .is_ok()
        );
        // Третий запрос в минуту — ждать почти минуту, а разрешено 5 с: отказ.
        assert!(
            acquire_patiently(&g, "sub.example.com", Duration::from_secs(5))
                .await
                .unwrap_err()
                .contains("повторите")
        );
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
