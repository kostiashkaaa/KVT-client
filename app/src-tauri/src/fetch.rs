//! Загрузка подписки по ссылке. Ссылка — секрет (в ней токен), поэтому она не
//! попадает ни в тексты ошибок, ни в логи.

use kvt_core::governor::{Decision, NetGovernor};
use kvt_core::netlog::{self, Origin, Purpose, Route};
use kvt_core::parser::parse_subscription_body;
use kvt_core::subscription::{
    hwid_signal, parse_headers, HwidSignal, SubscriptionMeta, Validators, MAX_BODY_BYTES,
};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

pub struct Fetched {
    pub meta: SubscriptionMeta,
    pub body: String,
    /// Под каким клиентом пришли серверы (ключ из `user_agents`) — с него начнём
    /// в следующий раз.
    pub agent: &'static str,
    /// Метки версии ответа: при следующем обновлении сервер может ответить 304.
    pub validators: Option<Validators>,
    /// Серверы пришли в ответ на запрос с ID устройства.
    pub hwid_sent: bool,
}

/// Итог загрузки подписки, которая уже есть.
pub enum Loaded {
    Fresh(Fetched),
    /// 304: подписка не изменилась, тела нет. Метаданные — из заголовков ответа
    /// (часто пустые), их надо наложить на прежние.
    NotModified(SubscriptionMeta),
}

/// Каким клиентом представляться провайдеру («Расширенные» у подписки).
#[derive(Clone, Copy, Default)]
pub enum Client<'a> {
    /// Очередь клиентов, пока в ответе не найдутся серверы.
    #[default]
    Auto,
    /// Только этот клиент (ключ из `PROFILES`).
    Profile(&'a str),
    /// Строка User-Agent целиком, как её ввёл пользователь.
    Custom(&'a str),
}

/// ID устройства (`x-hwid`).
#[derive(Clone, Copy, Default)]
pub enum Hwid<'a> {
    #[default]
    Off,
    /// Отправлять сразу.
    Send(&'a str),
    /// Только если провайдер скажет, что без него не отдаст серверы.
    OnRequest(&'a str),
}

/// Что известно с прошлой удачной загрузки и что задал пользователь.
#[derive(Default)]
pub struct Hints<'a> {
    pub client: Client<'a>,
    /// Клиент, под которым провайдер отдал серверы.
    pub agent: Option<&'a str>,
    /// Метки версии сохранённого тела. Только для запроса под тем же клиентом:
    /// другому клиенту провайдер отдаёт другой формат.
    pub validators: Option<&'a Validators>,
    pub hwid: Hwid<'a>,
}

/// Ответ на один запрос.
enum Reply {
    Body {
        meta: SubscriptionMeta,
        body: String,
        validators: Option<Validators>,
    },
    NotModified(SubscriptionMeta),
    /// Панель провайдера ждёт ID устройства (`x-hwid-not-supported`).
    HwidRequired,
}

fn hwid_required() -> &'static str {
    kvt_core::i18n::tr(
        "Провайдер ограничивает число устройств и ждёт ID устройства — разрешите его в «Расширенных» у подписки",
        "The provider limits devices and expects a device ID — allow it in the subscription's “Advanced”",
    )
}

fn hwid_rejected() -> &'static str {
    kvt_core::i18n::tr(
        "Провайдер не принял ID устройства — проверьте ID в «Расширенных» у подписки",
        "The provider rejected the device ID — check the ID in the subscription's “Advanced”",
    )
}

fn hwid_limit() -> &'static str {
    kvt_core::i18n::tr(
        "У провайдера достигнут лимит устройств — удалите лишнее устройство в личном кабинете провайдера",
        "The provider's device limit is reached — remove an extra device in your provider's account",
    )
}

pub fn validate_url(raw: &str) -> Result<Url, String> {
    // Ссылки «добавить в Happ / INCY / v2RayTun …» — в исходный адрес подписки.
    let unwrapped = kvt_core::subscription::unwrap_app_link(raw).map_err(str::to_owned)?;
    let raw = unwrapped.as_deref().unwrap_or(raw);
    let url = Url::parse(raw.trim()).map_err(|_| {
        kvt_core::i18n::tr(
            "Ссылка на подписку повреждена",
            "The subscription link is broken",
        )
        .to_string()
    })?;
    if url.scheme() != "https" {
        return Err(kvt_core::i18n::tr(
            "Подписка загружается только по https",
            "Subscriptions load over https only",
        )
        .into());
    }
    if url.host_str().is_none() {
        return Err(kvt_core::i18n::tr(
            "В ссылке нет адреса сервера",
            "The link has no server address",
        )
        .into());
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
        Decision::RetryAt(at) => Err(kvt_core::trf!(
            "Слишком частые запросы к серверу подписки — повторите через {} с",
            "Too many requests to the subscription server — try again in {} s",
            at.saturating_duration_since(now).as_secs().max(1)
        )),
        Decision::Frozen { until } => Err(kvt_core::trf!(
            "Провайдер интернета притормозил соединения с этим сервером — подождите {} с",
            "Your ISP stalled connections to this server — wait {} s",
            until.saturating_duration_since(now).as_secs().max(1)
        )),
    }
}

/// Новая подписка: условного запроса нет, ответ всегда с телом.
pub async fn fetch(url: &Url, hints: &Hints<'_>) -> Result<Fetched, String> {
    match load(url, hints).await? {
        Loaded::Fresh(fetched) => Ok(fetched),
        Loaded::NotModified(_) => Err(crate::errors::unexpected().into()),
    }
}

/// Обновление подписки: начинаем с клиента, который сработал в прошлый раз, и при
/// метках версии спрашиваем «изменилась ли».
pub async fn load(url: &Url, hints: &Hints<'_>) -> Result<Loaded, String> {
    let start = Instant::now();
    let result = fetch_inner(url, hints).await;
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
    match &result {
        Err(e) => event = event.detail(e),
        Ok(Loaded::NotModified(_)) => {
            event = event.detail(kvt_core::i18n::tr("не изменилась", "not changed"))
        }
        Ok(Loaded::Fresh(_)) => {}
    }
    netlog::record(event);
    result
}

/// Как KVT представляется серверу подписки. Панели провайдеров (Remnawave,
/// Marzban и др.) выбирают формат по User-Agent: незнакомому клиенту отвечают 404.
/// v2rayNG и Happ получают конфиги Xray в JSON — в них бывают серверы, которых нет в
/// списке ссылок (у провайдера из беты — все серверы Hysteria2); v2rayN 6 и Hiddify —
/// обычный список ссылок. Своё имя в строке остаётся — провайдер видит, кто пришёл.
/// Пробуем по очереди, пока в ответе не найдутся серверы; подписка запоминает, кто
/// сработал (ключ — без версии, чтобы смена версии в строке его не сбрасывала).
fn user_agent(key: &str) -> Option<String> {
    let kvt = concat!("KVT/", env!("CARGO_PKG_VERSION"));
    let client = match key {
        "v2rayng" => "v2rayNG/1.10.5",
        "v2rayn" => "v2rayN/6.60",
        "hiddify" => "Hiddify/2.5.7",
        // Часть провайдеров отдаёт серверы только «своему» клиенту Happ.
        "happ" => "Happ/3.6.1",
        // Только по выбору пользователя: в очередь не входят.
        "incy" => "INCY/3.3.4",
        "v2raytun" => "v2RayTun/5.19.62",
        "kvt" => return Some(kvt.to_owned()),
        _ => return None,
    };
    Some(format!("{client} {kvt}"))
}

/// Клиенты, которых можно выбрать у подписки.
pub const PROFILES: [&str; 7] = [
    "v2rayng", "v2rayn", "hiddify", "happ", "incy", "v2raytun", "kvt",
];
/// Очередь «Авто».
const QUEUE: [&str; 5] = ["v2rayng", "v2rayn", "hiddify", "happ", "kvt"];
/// Ключ, под которым запоминается свой User-Agent.
pub const CUSTOM: &str = "custom";

/// Очередь клиентов: выбранный пользователем — единственный; иначе запомненный —
/// первым, остальные в обычном порядке.
fn agent_order(client: Client<'_>, remembered: Option<&str>) -> Vec<(&'static str, String)> {
    let one = |key: &'static str| user_agent(key).map(|a| (key, a));
    match client {
        Client::Custom(agent) => vec![(CUSTOM, agent.to_owned())],
        Client::Profile(key) => match PROFILES.into_iter().find(|k| *k == key) {
            Some(k) => one(k).into_iter().collect(),
            None => agent_order(Client::Auto, remembered),
        },
        Client::Auto => {
            let mut agents: Vec<_> = QUEUE.into_iter().filter_map(one).collect();
            if let Some(i) = agents.iter().position(|(key, _)| Some(*key) == remembered) {
                let first = agents.remove(i);
                agents.insert(0, first);
            }
            agents
        }
    }
}

/// Сколько перенаправлений проходит загрузка подписки.
const MAX_REDIRECTS: usize = 3;

/// Один клиент на всю загрузку: перебор User-Agent и повтор с ID устройства идут по
/// одному соединению (keep-alive), а не открывают новое TLS-рукопожатие к тому же
/// SNI на каждую попытку — разрешение NetGovernor у загрузки одно. Перенаправления
/// — вручную (`fetch_as`): ID устройства не должен уйти на чужой хост.
fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(describe)
}

async fn fetch_inner(url: &Url, hints: &Hints<'_>) -> Result<Loaded, String> {
    let client = client()?;
    let mut first_error = None;
    let mut hwid = match hints.hwid {
        Hwid::Send(id) => Some(id),
        _ => None,
    };
    for (key, agent) in agent_order(hints.client, hints.agent) {
        let conditional = hints.validators.filter(|_| hints.agent == Some(key));
        let mut reply = fetch_as(&client, url, &agent, conditional, hwid).await;
        if let (Ok(Reply::HwidRequired), Hwid::OnRequest(id)) = (&reply, hints.hwid) {
            // Провайдер сам сказал, что без ID не отдаст: повтор с ним, и дальше
            // по очереди — тоже с ним.
            hwid = Some(id);
            reply = fetch_as(&client, url, &agent, conditional, hwid).await;
        }
        match reply {
            Ok(Reply::NotModified(meta)) => return Ok(Loaded::NotModified(meta)),
            // Другой клиент тут не поможет.
            Ok(Reply::HwidRequired) => {
                return Err(if hwid.is_some() {
                    hwid_rejected()
                } else {
                    hwid_required()
                }
                .into())
            }
            Ok(Reply::Body {
                meta,
                body,
                validators,
            }) => {
                let fetched = Fetched {
                    meta,
                    body,
                    agent: key,
                    validators,
                    hwid_sent: hwid.is_some(),
                };
                if !parse_subscription_body(&fetched.body).servers.is_empty() {
                    return Ok(Loaded::Fresh(fetched));
                }
                // Ответ есть, но не в понятном KVT формате — пробуем следующего клиента.
                first_error.get_or_insert(Ok(Loaded::Fresh(fetched)));
            }
            Err(e) => {
                first_error.get_or_insert(Err(e));
            }
        }
    }
    // Ни один вариант не дал серверов: вернуть первое, что было (ошибку или ответ —
    // тогда «не нашлось серверов» скажет проверка подписки).
    first_error.unwrap_or_else(|| {
        Err(kvt_core::i18n::tr(
            "Не удалось загрузить подписку",
            "Couldn't load the subscription",
        )
        .into())
    })
}

/// Хост и порт совпадают (схема у подписок — только https).
fn same_host(a: &Url, b: &Url) -> bool {
    a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

async fn fetch_as(
    client: &reqwest::Client,
    url: &Url,
    agent: &str,
    conditional: Option<&Validators>,
    hwid: Option<&str>,
) -> Result<Reply, String> {
    let mut target = url.clone();
    let mut send_hwid = hwid;
    let mut answer = None;
    for _ in 0..=MAX_REDIRECTS {
        let mut request = client
            .get(target.clone())
            .header(reqwest::header::USER_AGENT, agent);
        if let Some(v) = conditional {
            if let Some(etag) = &v.etag {
                request = request.header(reqwest::header::IF_NONE_MATCH, etag);
            }
            if let Some(date) = &v.last_modified {
                request = request.header(reqwest::header::IF_MODIFIED_SINCE, date);
            }
        }
        if let Some(id) = send_hwid {
            // Как у Happ: ID и общие сведения об устройстве, без имени компьютера.
            request = request
                .header("x-hwid", id)
                .header("x-device-os", "Windows")
                .header("x-device-model", "KVT");
        }
        let resp = request.send().await.map_err(describe)?;
        let next = resp
            .status()
            .is_redirection()
            .then(|| resp.headers().get(reqwest::header::LOCATION))
            .flatten()
            .and_then(|l| l.to_str().ok())
            .and_then(|l| target.join(l).ok());
        let Some(next) = next else {
            answer = Some(resp);
            break;
        };
        // ID устройства — только хосту подписки, как reqwest поступает с Authorization.
        if !same_host(&next, url) {
            send_hwid = None;
        }
        target = next;
    }
    let Some(mut resp) = answer else {
        return Err(kvt_core::i18n::tr(
            "Сервер подписки перенаправляет слишком много раз",
            "The subscription server redirects too many times",
        )
        .into());
    };
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    let pairs = || headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    match hwid_signal(pairs()) {
        Some(HwidSignal::LimitReached) => return Err(hwid_limit().into()),
        Some(HwidSignal::Required) if hwid.is_none() => return Ok(Reply::HwidRequired),
        _ => {}
    }
    let meta = parse_headers(pairs());
    // 304 принимаем, только если сами спрашивали «изменилась ли».
    if conditional.is_some() && resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(Reply::NotModified(meta));
    }
    if !resp.status().is_success() {
        return Err(kvt_core::trf!(
            "Сервер подписки ответил ошибкой {}",
            "The subscription server returned error {}",
            resp.status().as_u16()
        ));
    }
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
    {
        return Err(kvt_core::i18n::tr(
            "Подписка слишком большая",
            "The subscription is too large",
        )
        .into());
    }

    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(describe)? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(kvt_core::i18n::tr(
                "Подписка слишком большая",
                "The subscription is too large",
            )
            .into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Reply::Body {
        meta,
        body: String::from_utf8_lossy(&body).into_owned(),
        validators: Validators::from_headers(pairs()),
    })
}

/// Человеческое описание ошибки без URL (в нём токен подписки).
fn describe(e: reqwest::Error) -> String {
    let e = e.without_url();
    use kvt_core::i18n::tr;
    if e.is_timeout() {
        tr(
            "Сервер подписки не ответил вовремя",
            "The subscription server didn't respond in time",
        )
        .into()
    } else if e.is_connect() {
        tr(
            "Не удалось подключиться к серверу подписки — возможно, он заблокирован. Включите VPN и повторите",
            "Couldn't connect to the subscription server — it may be blocked. Turn on the VPN and try again",
        )
        .into()
    } else if e.is_redirect() {
        tr(
            "Сервер подписки перенаправляет слишком много раз",
            "The subscription server redirects too many times",
        )
        .into()
    } else {
        kvt_core::trf!(
            "Не удалось загрузить подписку: {e}",
            "Couldn't load the subscription: {e}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::governor::NetPolicy;

    #[test]
    fn known_clients_first_own_name_kept() {
        let agents = agent_order(Client::Auto, None);
        assert!(agents[0].1.starts_with("v2rayNG/"));
        assert!(agents.iter().all(|(_, a)| a.contains("KVT/")));
        assert!(PROFILES.iter().all(|k| user_agent(k).is_some()));
    }

    #[test]
    fn chosen_client_is_the_only_one() {
        let incy = agent_order(Client::Profile("incy"), Some("happ"));
        assert_eq!(incy.len(), 1);
        assert!(incy[0].1.starts_with("INCY/"));
        let custom = agent_order(Client::Custom("Happ/3.7.0"), None);
        assert_eq!(custom, [(CUSTOM, "Happ/3.7.0".to_owned())]);
        // Профиля, которого больше нет, — обычная очередь.
        assert_eq!(
            agent_order(Client::Profile("clash"), None).len(),
            QUEUE.len()
        );
    }

    #[test]
    fn remembered_client_goes_first() {
        let keys = |r| {
            agent_order(Client::Auto, r)
                .into_iter()
                .map(|(k, _)| k)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            keys(Some("happ")),
            ["happ", "v2rayng", "v2rayn", "hiddify", "kvt"]
        );
        assert_eq!(keys(None), ["v2rayng", "v2rayn", "hiddify", "happ", "kvt"]);
        // Ключ, которого больше нет, — обычный порядок.
        assert_eq!(keys(Some("clash")), keys(None));
    }

    /// Настоящая подписка: `KVT_SUB_URL=https://… cargo test -p kvt-app real_subscription -- --ignored`.
    #[tokio::test]
    #[ignore = "ходит в сеть по ссылке из KVT_SUB_URL"]
    async fn real_subscription() {
        let url = validate_url(&std::env::var("KVT_SUB_URL").unwrap()).unwrap();
        let fetched = fetch(&url, &Hints::default()).await.unwrap();
        let n = parse_subscription_body(&fetched.body).servers.len();
        println!("серверов: {n}");
        assert!(n > 0);
    }

    /// ID устройства не уходит при перенаправлении на другой хост.
    #[test]
    fn redirect_to_another_host_is_not_the_same_host() {
        let sub = Url::parse("https://sub.example.com/abc").unwrap();
        assert!(same_host(
            &sub,
            &Url::parse("https://sub.example.com/x?y").unwrap()
        ));
        assert!(same_host(
            &sub,
            &Url::parse("https://SUB.example.com:443/").unwrap()
        ));
        assert!(!same_host(
            &sub,
            &Url::parse("https://cdn.example.net/abc").unwrap()
        ));
        assert!(!same_host(
            &sub,
            &Url::parse("https://sub.example.com:8443/").unwrap()
        ));
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
