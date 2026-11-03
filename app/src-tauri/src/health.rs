//! Проверка, что через туннель действительно идут данные. Один маленький HTTP-запрос
//! (`kvt_core::routing::HEALTH_URL`, ответ меньше 200 байт) — служба маршрутизирует
//! его через VPN в любом режиме. Клиент держит соединение открытым (keep-alive),
//! поэтому регулярная проверка обычно не открывает новых соединений к серверу.

use kvt_core::routing::HEALTH_URL;
use serde::Serialize;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    /// Страна выхода (код ISO), как её видит Cloudflare.
    pub country: Option<String>,
    pub ms: u64,
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_default()
}

pub async fn check(client: &reqwest::Client) -> Result<Trace, String> {
    let start = Instant::now();
    let response = client.get(HEALTH_URL).send().await.map_err(|e| {
        if e.is_timeout() {
            "нет ответа".into()
        } else {
            e.to_string()
        }
    })?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    let body = response.text().await.map_err(|e| e.to_string())?;
    Ok(Trace {
        country: country(&body),
        ms: start.elapsed().as_millis() as u64,
    })
}

/// Строка `loc=NL` из ответа `/cdn-cgi/trace`.
fn country(body: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix("loc="))
        .map(str::trim)
        .filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic()))
        .map(str::to_ascii_uppercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_parsing() {
        let body = "fl=12f\nh=www.cloudflare.com\nip=203.0.113.7\nloc=DK\ncolo=CPH\n";
        assert_eq!(country(body).as_deref(), Some("DK"));
        assert_eq!(country("loc=<script>"), None);
        assert_eq!(country(""), None);
    }
}
