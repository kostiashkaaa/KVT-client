//! HTTP-клиент службы для списков и комплекта zapret. Один клиент с пулом
//! соединений: все файлы с одного хоста идут через одно TLS-соединение.
//!
//! Если VPN подключён ([`NetClient::with_tunnel_fallback`]), запрос сначала идёт
//! напрямую — сокет привязан к адресу физического адаптера и минует TUN, — а
//! если не вышло, повторяется через туннель: эти адреса (`UPDATE_HOSTS`) план
//! маршрутизации отправляет через VPN. Часть провайдеров тормозит GitHub, и от
//! одного пути зависеть нельзя.

use kvt_core::captive;
use kvt_core::dns::names::Lookup;
use kvt_core::governor::{NetGovernor, NetPolicy};
use kvt_core::ipc::{Captive, PingTarget, Response, MAX_PING_TARGETS};
use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::rulesync::Http;
use kvt_core::tester::Doh;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, Mutex};
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
        return Err(kvt_core::trf!(
            "сервер ответил ошибкой {}",
            "the server returned error {}",
            resp.status().as_u16()
        ));
    }
    if resp.content_length().is_some_and(|l| l > max_bytes as u64) {
        return Err(kvt_core::i18n::tr("слишком большой ответ", "response too large").into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(describe)? {
        if body.len() + chunk.len() > max_bytes {
            return Err(kvt_core::i18n::tr("слишком большой ответ", "response too large").into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Ошибка сети по-русски; исходный текст — в журнал службы.
fn describe(e: reqwest::Error) -> String {
    let e = e.without_url();
    tracing::debug!(error = %e, "ошибка сети");
    use kvt_core::i18n::tr;
    if e.is_timeout() {
        tr(
            "сервер не ответил вовремя",
            "the server didn't respond in time",
        )
        .into()
    } else if e.is_connect() {
        tr(
            "не удалось подключиться — сайт недоступен или заблокирован",
            "couldn't connect — the site is unreachable or blocked",
        )
        .into()
    } else if e.is_redirect() {
        tr("слишком много перенаправлений", "too many redirects").into()
    } else if e.is_body() || e.is_decode() {
        tr(
            "соединение оборвалось во время загрузки",
            "the connection dropped during download",
        )
        .into()
    } else {
        tr("ошибка сети", "network error").into()
    }
}

/// NetGovernor службы: её запросы к резолверам DoH (имена серверов для пинга).
static GOVERNOR: LazyLock<Mutex<NetGovernor>> =
    LazyLock::new(|| Mutex::new(NetGovernor::new(NetPolicy::default())));

/// TCP-пинг серверов напрямую через физический адаптер: окно при подключённом
/// VPN пингует через TUN, и тот принимает соединение сам — за 0 мс. Имена — через
/// DoH (`doh` — первый резолвер) тоже мимо туннеля: если VPN не работает, пинг
/// должен это показать, а не застрять на DNS.
pub async fn ping(targets: Vec<Option<PingTarget>>, doh: &str) -> Response {
    if targets.len() > MAX_PING_TARGETS {
        return Response::Error {
            message: kvt_core::i18n::tr(
                "Слишком много серверов для пинга за раз",
                "Too many servers to ping at once",
            )
            .into(),
        };
    }
    let Some(local) = crate::wfp::physical_ipv4() else {
        return Response::Error {
            message: kvt_core::i18n::tr(
                "Не найден сетевой адаптер для пинга мимо VPN",
                "No network adapter found to ping outside the VPN",
            )
            .into(),
        };
    };
    let targets: Vec<Option<(String, u16)>> = targets
        .into_iter()
        .map(|t| t.map(|t| (t.host, t.port)))
        .collect();
    Response::Ping {
        results: kvt_core::tester::ping_all(
            &targets,
            &Doh {
                first: doh,
                governor: &GOVERNOR,
            },
            Some(local),
            Origin::Service,
            Duration::from_secs(3),
            8,
        )
        .await,
    }
}

/// IP, в которые последний раз разрешились имена серверов (ключ — имя в нижнем
/// регистре). Нужны, когда DoH не отвечает: тогда подключение берёт прежние адреса,
/// а не спрашивает DNS провайдера.
static RESOLVED: Mutex<Option<HashMap<String, Vec<IpAddr>>>> = Mutex::new(None);

/// Последние известные IP имени (без запроса в сеть).
pub fn known_ips(host: &str) -> Vec<IpAddr> {
    RESOLVED
        .lock()
        .ok()
        .and_then(|r| r.as_ref()?.get(&host.to_ascii_lowercase()).cloned())
        .unwrap_or_default()
}

/// Сколько подключение ждёт DoH, прежде чем взять прежние адреса.
const CONNECT_DOH_BUDGET: Duration = Duration::from_secs(5);

/// Адреса имён VPN-сервера (`Server::endpoints`; IP из ссылки не входят) для ядра,
/// маскировщика журналов и исключений zapret. Через DoH (`doh` — первый резолвер)
/// мимо туннеля, с адреса физического адаптера: прежний туннель при переподключении
/// может быть мёртв, а kill switch службу пропускает. DoH не ответил — прежние
/// адреса имени; их нет — системный DNS (до 5 с) с предупреждением в журнале: без
/// адреса не подключиться, хотя этот запрос и видит провайдер.
pub async fn server_ips(names: &[String], port: u16, doh: &str) -> Vec<(String, Vec<IpAddr>)> {
    let names: Vec<String> = names
        .iter()
        .filter(|n| n.trim_matches(['[', ']']).parse::<IpAddr>().is_err())
        .cloned()
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    let doh = Doh {
        first: doh,
        governor: &GOVERNOR,
    };
    let local = crate::wfp::physical_ipv4();
    let lookup = kvt_core::dns::names::resolve(&names, &doh, local, Origin::Service);
    let found = tokio::time::timeout(CONNECT_DOH_BUDGET, lookup)
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for name in names {
        let ips = match found.get(&name) {
            Some(Lookup::Found(ips)) => ips.clone(),
            // DoH ответил «такого имени нет» — системный DNS не спрашиваем.
            Some(Lookup::NotFound) => known_ips(&name),
            _ => fallback(&name, port).await,
        };
        if ips.is_empty() {
            continue;
        }
        if let Ok(mut r) = RESOLVED.lock() {
            r.get_or_insert_with(HashMap::new)
                .insert(name.to_ascii_lowercase(), ips.clone());
        }
        out.push((name, ips));
    }
    out
}

async fn fallback(host: &str, port: u16) -> Vec<IpAddr> {
    let known = known_ips(host);
    if !known.is_empty() {
        tracing::info!("DoH не ответил — взяты прежние адреса сервера");
        return known;
    }
    tracing::warn!("DoH не ответил — адрес сервера спрошен у системного DNS");
    let start = Instant::now();
    let mut found: Vec<IpAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(|addrs| addrs.map(|a| a.ip()).collect())
    .unwrap_or_default();
    found.sort();
    found.dedup();
    record_lookup(host, !found.is_empty(), start);
    found
}

/// Системный DNS-запрос имени VPN-сервера (запасной путь, когда DoH не ответил) —
/// в журнал запросов, как и всё, что служба отправляет в сеть.
fn record_lookup(host: &str, ok: bool, start: Instant) {
    let outcome = if ok { Outcome::Ok } else { Outcome::Failed };
    netlog::record(
        netlog::Event::new(Origin::Service, Purpose::Dns, host, Route::Direct, outcome)
            .ms(start.elapsed())
            .detail(kvt_core::i18n::tr(
                "адрес сервера через системный DNS: DoH не ответил",
                "server address via system DNS: DoH didn't answer",
            )),
    );
}

/// Ответил ли по HTTPS хоть один DoH-резолвер из каталога KVT. IP задан заранее,
/// сертификат проверяется по имени — такой ответ не подделает ни страница входа,
/// ни провайдер. HTTP провайдер подменить может: у пользователя с перехватом DNS
/// запрос к `http://1.1.1.1` получал чужой ответ, KVT считал, что сеть просит
/// войти, и автопереключение не меняло мёртвый сервер (2026-11-07).
async fn https_reachable(local: Option<Ipv4Addr>) -> bool {
    let endpoints: Vec<_> = kvt_core::dns::RESOLVERS
        .iter()
        .filter_map(|r| r.doh)
        .collect();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(5))
        .local_address(local.map(IpAddr::V4));
    for ep in &endpoints {
        builder = builder.resolve(ep.host, SocketAddr::from((ep.ip, 443)));
    }
    let Ok(client) = builder.build() else {
        return false;
    };
    let mut probes = tokio::task::JoinSet::new();
    for ep in endpoints {
        let client = client.clone();
        probes.spawn(async move {
            let start = Instant::now();
            let ok = client
                .get(format!("https://{}/", ep.host))
                .send()
                .await
                .is_ok();
            let outcome = if ok { Outcome::Ok } else { Outcome::Failed };
            netlog::record(
                netlog::Event::new(
                    Origin::Service,
                    Purpose::Captive,
                    ep.host,
                    Route::Direct,
                    outcome,
                )
                .ms(start.elapsed()),
            );
            ok
        });
    }
    // Первый же ответ решает; остальные запросы отменяются вместе с JoinSet.
    while let Some(done) = probes.join_next().await {
        if done.unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Сколько ответа читать при проверке страницы входа: известные ответы — десятки
/// байт, а страница входа сети может прислать сколько угодно (память службы).
const CAPTIVE_BODY: usize = 64 * 1024;

/// Начало тела ответа, не больше `max` байт; остальное не читается. Длиннее
/// известного ответа — значит, не он, и для `captive::classify` начала хватает.
async fn head_of(mut resp: reqwest::Response, max: usize) -> String {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        let room = max.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if body.len() >= max {
            break;
        }
    }
    String::from_utf8_lossy(&body).into_owned()
}

/// Просит ли сеть войти (отель, кафе). Запрос идёт напрямую через физический
/// адаптер: TUN и kill switch его не задерживают (служба в списке разрешённых).
/// Сначала HTTPS к известным серверам: если он проходит, страницы входа нет.
/// Иначе — HTTP-запрос с заранее известным ответом, как у Windows.
pub async fn captive_check() -> Captive {
    let local = crate::wfp::physical_ipv4();
    if https_reachable(local).await {
        tracing::info!(result = ?Captive::Online, "проверка страницы входа: HTTPS отвечает");
        return Captive::Online;
    }
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
                // Куда отправляет чужой ответ — только хост, без пути и параметров.
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|u| reqwest::Url::parse(u).ok())
                    .and_then(|u| u.host_str().map(str::to_owned));
                let body = head_of(resp, CAPTIVE_BODY).await;
                let state = captive::classify(status, &body);
                if state == Captive::Portal {
                    tracing::info!(
                        status,
                        ?location,
                        bytes = body.len(),
                        "проверка страницы входа: чужой ответ по HTTP"
                    );
                }
                Some(state)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Ходит в интернет: `cargo test -p kvt-service -- --ignored https_probe`.
    #[tokio::test]
    #[ignore]
    async fn https_probe_reaches_known_resolvers() {
        assert!(https_reachable(None).await);
        assert_eq!(captive_check().await, Captive::Online);
    }
}
