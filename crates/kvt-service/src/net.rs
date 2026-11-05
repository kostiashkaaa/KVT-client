//! HTTP-клиент службы для списков и комплекта zapret. Один клиент с пулом
//! соединений: все файлы с одного хоста идут через одно TLS-соединение.
//!
//! Если VPN подключён ([`NetClient::with_tunnel_fallback`]), запрос сначала идёт
//! напрямую — сокет привязан к адресу физического адаптера и минует TUN, — а
//! если не вышло, повторяется через туннель: эти адреса (`UPDATE_HOSTS`) план
//! маршрутизации отправляет через VPN. Часть провайдеров тормозит GitHub, и от
//! одного пути зависеть нельзя.

use kvt_core::captive;
use kvt_core::ipc::{Captive, PingTarget, Response, MAX_PING_TARGETS};
use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::rulesync::Http;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

pub struct NetClient {
    /// Обычный клиент: без VPN — напрямую, с VPN — по маршрутизации (через туннель).
    client: reqwest::Client,
    /// Клиент в обход TUN — только при подключённом VPN.
    direct: Option<reqwest::Client>,
    /// Зачем служба ходит в сеть — для журнала запросов.
    purpose: Purpose,
}

fn build(local: Option<Ipv4Addr>) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .local_address(local.map(IpAddr::V4))
        // API GitHub требует User-Agent.
        .user_agent(concat!("KVT/", env!("CARGO_PKG_VERSION")))
        .build()
}

impl NetClient {
    pub fn new(purpose: Purpose) -> anyhow::Result<Self> {
        Ok(Self {
            client: build(None)?,
            direct: None,
            purpose,
        })
    }

    /// VPN подключён: сначала напрямую мимо TUN, при неудаче — через туннель.
    pub fn with_tunnel_fallback(mut self) -> Self {
        self.direct = crate::wfp::physical_ipv4().and_then(|ip| build(Some(ip)).ok());
        self
    }

    fn record(&self, url: &str, route: Route, start: Instant, result: &Result<Vec<u8>, String>) {
        let outcome = if result.is_ok() {
            Outcome::Ok
        } else {
            Outcome::Failed
        };
        let mut event = netlog::Event::new(
            Origin::Service,
            self.purpose,
            &netlog::host_of(url),
            route,
            outcome,
        )
        .ms(start.elapsed());
        if let Err(e) = result {
            event = event.detail(e);
        }
        netlog::record(event);
    }
}

impl Http for NetClient {
    async fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
        if let Some(direct) = &self.direct {
            let start = Instant::now();
            let result = get_with(direct, url, max_bytes).await;
            self.record(url, Route::Direct, start, &result);
            if result.is_ok() {
                return result;
            }
            tracing::info!(host = %netlog::host_of(url), "напрямую не вышло — повтор через туннель");
            let start = Instant::now();
            let result = get_with(&self.client, url, max_bytes).await;
            self.record(url, Route::Tunnel, start, &result);
            return result;
        }
        let start = Instant::now();
        let result = get_with(&self.client, url, max_bytes).await;
        self.record(url, Route::Direct, start, &result);
        result
    }
}

async fn get_with(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut resp = client.get(url).send().await.map_err(describe)?;
    if !resp.status().is_success() {
        return Err(format!("сервер ответил ошибкой {}", resp.status().as_u16()));
    }
    if resp.content_length().is_some_and(|l| l > max_bytes as u64) {
        return Err("слишком большой ответ".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(describe)? {
        if body.len() + chunk.len() > max_bytes {
            return Err("слишком большой ответ".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Ошибка сети по-русски; исходный текст — в журнал службы.
fn describe(e: reqwest::Error) -> String {
    let e = e.without_url();
    tracing::debug!(error = %e, "ошибка сети");
    if e.is_timeout() {
        "сервер не ответил вовремя".into()
    } else if e.is_connect() {
        "не удалось подключиться — сайт недоступен или заблокирован".into()
    } else if e.is_redirect() {
        "слишком много перенаправлений".into()
    } else if e.is_body() || e.is_decode() {
        "соединение оборвалось во время загрузки".into()
    } else {
        "ошибка сети".into()
    }
}

/// TCP-пинг серверов напрямую через физический адаптер: окно при подключённом
/// VPN пингует через TUN, и тот принимает соединение сам — за 0 мс.
pub async fn ping(targets: Vec<Option<PingTarget>>) -> Response {
    if targets.len() > MAX_PING_TARGETS {
        return Response::Error {
            message: "Слишком много серверов для пинга за раз".into(),
        };
    }
    let Some(local) = crate::wfp::physical_ipv4() else {
        return Response::Error {
            message: "Не найден сетевой адаптер для пинга мимо VPN".into(),
        };
    };
    let targets: Vec<Option<(String, u16)>> = targets
        .into_iter()
        .map(|t| t.map(|t| (t.host, t.port)))
        .collect();
    Response::Ping {
        results: kvt_core::tester::ping_all(
            &targets,
            Some(local),
            Origin::Service,
            Duration::from_secs(3),
            8,
        )
        .await,
    }
}

/// Просит ли сеть войти (отель, кафе). Запрос идёт напрямую через физический
/// адаптер: TUN и kill switch его не задерживают (служба в списке разрешённых).
pub async fn captive_check() -> Captive {
    let local = crate::wfp::physical_ipv4();
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(6))
        .local_address(local.map(IpAddr::V4))
        .build()
    else {
        return Captive::Offline;
    };
    let mut result = Captive::Offline;
    for url in captive::PROBE_URLS {
        let start = Instant::now();
        let answer = match client.get(*url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                Some(captive::classify(status, &body))
            }
            Err(_) => None,
        };
        let outcome = if answer.is_some() {
            Outcome::Ok
        } else {
            Outcome::Failed
        };
        netlog::record(
            netlog::Event::new(
                Origin::Service,
                Purpose::Captive,
                &netlog::host_of(url),
                Route::Direct,
                outcome,
            )
            .ms(start.elapsed()),
        );
        match answer {
            Some(state) => {
                result = state;
                break;
            }
            None => continue,
        }
    }
    tracing::info!(?result, "проверка страницы входа");
    result
}
