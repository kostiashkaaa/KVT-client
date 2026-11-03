//! HTTP-клиент службы для обновления списков. Один клиент с пулом соединений:
//! все файлы с одного хоста идут через одно TLS-соединение, без серии рукопожатий.

use kvt_core::rulesync::Http;
use std::time::Duration;

pub struct NetClient {
    client: reqwest::Client,
}

impl NetClient {
    pub fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            // API GitHub требует User-Agent.
            .user_agent(concat!("KVT/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client })
    }
}

impl Http for NetClient {
    async fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
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
