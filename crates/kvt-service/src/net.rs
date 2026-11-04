//! HTTP-клиент службы для обновления списков. Один клиент с пулом соединений:
//! все файлы с одного хоста идут через одно TLS-соединение, без серии рукопожатий.

use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::rulesync::Http;
use std::time::{Duration, Instant};

pub struct NetClient {
    client: reqwest::Client,
    /// Зачем служба ходит в сеть — для журнала запросов.
    purpose: Purpose,
}

impl NetClient {
    pub fn new(purpose: Purpose) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            // API GitHub требует User-Agent.
            .user_agent(concat!("KVT/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client, purpose })
    }
}

impl Http for NetClient {
    async fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
        let start = Instant::now();
        let result = self.get_inner(url, max_bytes).await;
        let outcome = if result.is_ok() {
            Outcome::Ok
        } else {
            Outcome::Failed
        };
        let mut event = netlog::Event::new(
            Origin::Service,
            self.purpose,
            &netlog::host_of(url),
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
}

impl NetClient {
    async fn get_inner(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
        let mut resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status().as_u16()));
        }
        if resp.content_length().is_some_and(|l| l > max_bytes as u64) {
            return Err("слишком большой ответ".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| e.without_url().to_string())?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err("слишком большой ответ".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
