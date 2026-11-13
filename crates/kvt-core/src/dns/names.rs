//! Адреса VPN-серверов для проверки — через DoH, а не системный DNS.
//!
//! Системный DNS — обычно резолвер провайдера: по запросам он видел бы весь список
//! серверов подписки, который проверяет KVT. Поэтому имена спрашиваем по HTTPS:
//! сначала у резолвера, выбранного в настройках для туннеля, при отказе — у
//! остальных DoH из каталога. Не ответил ни один — «адрес не найден», без тихого
//! отката на системный DNS.
//!
//! Резолверы — по своим IP из каталога, так что системный DNS не нужен и для них.
//! Клиент один на процесс (и на адрес источника): запросы к резолверу идут по одному
//! соединению HTTP/2, новое соединение — по решению NetGovernor. Найденные адреса
//! помнятся 10 минут: «Проверить» пингует серверы, а потом полная проверка — каждый
//! ещё раз.

use super::{wire, Endpoint, RESOLVERS};
use crate::governor::{Decision, NetGovernor};
use crate::netlog::{self, Origin, Purpose, Route};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const CACHE_FOR: Duration = Duration::from_secs(10 * 60);
const CACHE_MAX: usize = 4096;
/// Соединение, простоявшее дольше, считаем закрытым: следующий запрос откроет новое
/// и сначала спросит NetGovernor. Клиент держит простаивающее соединение дольше
/// (`POOL_IDLE`), так что «тёплое» по нашему счёту ещё открыто.
const IDLE: Duration = Duration::from_secs(30);
const POOL_IDLE: Duration = Duration::from_secs(90);
/// Резолвер, не ответивший ни на один запрос, столько не спрашиваем.
const DEAD_FOR: Duration = Duration::from_secs(60);
const PARALLEL: usize = 8;

/// Какой DoH спрашивать первым и NetGovernor процесса.
pub struct Doh<'a> {
    /// id резолвера из [`RESOLVERS`]; незнакомый — просто порядок каталога.
    pub first: &'a str,
    pub governor: &'a Mutex<NetGovernor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Found(Vec<IpAddr>),
    /// Резолвер ответил: такого имени нет или у него нет адресов.
    NotFound,
    /// Ни один DoH не ответил.
    Failed,
}

/// Адреса имён `hosts` (как в ссылках серверов; IP возвращаются как есть). `local` —
/// адрес источника: служба при подключённом VPN спрашивает мимо туннеля.
pub async fn resolve(
    hosts: &[String],
    doh: &Doh<'_>,
    local: Option<Ipv4Addr>,
    origin: Origin,
) -> HashMap<String, Lookup> {
    let client = client(local);
    let query = move |endpoint: Endpoint, name: String| {
        let client = client.clone();
        async move { ask(client?, endpoint, name).await }
    };
    resolve_with(&BOOK, local, hosts, doh, origin, query).await
}

static BOOK: LazyLock<Mutex<Book>> = LazyLock::new(Mutex::default);
static CLIENTS: LazyLock<Mutex<HashMap<Option<Ipv4Addr>, reqwest::Client>>> =
    LazyLock::new(Mutex::default);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Порядок опроса: выбранный резолвер, затем остальные DoH каталога.
fn order(first: &str) -> Vec<Endpoint> {
    let chosen = RESOLVERS.iter().filter(|r| r.id == first);
    let rest = RESOLVERS.iter().filter(|r| r.id != first);
    chosen.chain(rest).filter_map(|r| r.doh).collect()
}

/// IP в ссылке (IPv6 бывает в квадратных скобках) — спрашивать нечего.
fn literal(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Адреса, по которым пинговать нечего: так резолверы с фильтрами отвечают на
/// заблокированные имена, а `127.0.0.1` «ответил» бы за любой сервер.
fn usable(ips: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
        .collect()
}

#[derive(Debug, Default)]
struct Conn {
    last_used: Option<Instant>,
    dead_until: Option<Instant>,
}

/// Соединения с резолверами (по нашему счёту) и найденные адреса.
#[derive(Debug, Default)]
struct Book {
    conns: HashMap<(Option<Ipv4Addr>, &'static str), Conn>,
    cache: HashMap<String, (Instant, Vec<IpAddr>)>,
}

impl Book {
    fn cached(&self, name: &str, now: Instant) -> Option<Vec<IpAddr>> {
        self.cache
            .get(name)
            .filter(|(at, _)| now.saturating_duration_since(*at) < CACHE_FOR)
            .map(|(_, ips)| ips.clone())
    }

    fn remember(&mut self, name: String, ips: Vec<IpAddr>, now: Instant) {
        if self.cache.len() >= CACHE_MAX {
            self.cache
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < CACHE_FOR);
            if self.cache.len() >= CACHE_MAX {
                self.cache.clear();
            }
        }
        self.cache.insert(name, (now, ips));
    }

    /// `Ok` — спрашивать; `Err(Some)` — NetGovernor не дал открыть новое соединение;
    /// `Err(None)` — резолвер недавно не ответил.
    fn admit(
        &mut self,
        local: Option<Ipv4Addr>,
        host: &'static str,
        now: Instant,
        acquire: impl FnOnce() -> Decision,
    ) -> Result<(), Option<Decision>> {
        let conn = self.conns.entry((local, host)).or_default();
        if conn.dead_until.is_some_and(|t| now < t) {
            return Err(None);
        }
        let warm = conn
            .last_used
            .is_some_and(|t| now.saturating_duration_since(t) < IDLE);
        if !warm {
            match acquire() {
                Decision::Allowed => {}
                other => return Err(Some(other)),
            }
        }
        // Сразу, а не после ответа: параллельный опрос не должен считать то же
        // соединение новым.
        conn.last_used = Some(now);
        conn.dead_until = None;
        Ok(())
    }

    fn finish(
        &mut self,
        local: Option<Ipv4Addr>,
        host: &'static str,
        answered: bool,
        now: Instant,
    ) {
        let conn = self.conns.entry((local, host)).or_default();
        if answered {
            conn.last_used = Some(now);
        } else {
            conn.last_used = None;
            conn.dead_until = Some(now + DEAD_FOR);
        }
    }
}

/// Сам опрос; `query` — один запрос имени к резолверу (`Ok(пусто)` — имени нет).
/// Вынесено ради тестов без сети.
async fn resolve_with<Q, F>(
    book: &Mutex<Book>,
    local: Option<Ipv4Addr>,
    hosts: &[String],
    doh: &Doh<'_>,
    origin: Origin,
    query: Q,
) -> HashMap<String, Lookup>
where
    Q: Fn(Endpoint, String) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<Vec<IpAddr>, String>> + Send + 'static,
{
    let mut out = HashMap::new();
    let mut wanted: Vec<(String, String)> = Vec::new();
    let mut remaining: Vec<String> = Vec::new();
    let now = Instant::now();
    for host in hosts {
        if out.contains_key(host) || wanted.iter().any(|(h, _)| h == host) {
            continue;
        }
        if let Some(ip) = literal(host) {
            out.insert(host.clone(), Lookup::Found(vec![ip]));
            continue;
        }
        let name = normalize(host);
        // Не имя (пусто, не ASCII, слишком длинное) — спрашивать нечего.
        if wire::query(0, &name, wire::TYPE_A).is_err() {
            out.insert(host.clone(), Lookup::NotFound);
            continue;
        }
        if let Some(ips) = lock(book).cached(&name, now) {
            out.insert(host.clone(), Lookup::Found(ips));
            continue;
        }
        if !remaining.contains(&name) {
            remaining.push(name.clone());
        }
        wanted.push((host.clone(), name));
    }

    let mut answers: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for endpoint in order(doh.first) {
        if remaining.is_empty() {
            break;
        }
        let now = Instant::now();
        let admitted = lock(book).admit(local, endpoint.host, now, || {
            lock(doh.governor).try_acquire(endpoint.host, now)
        });
        match admitted {
            Ok(()) => {}
            Err(Some(decision)) => {
                netlog::record_hold(
                    origin,
                    Purpose::Dns,
                    endpoint.host,
                    Route::Direct,
                    &decision,
                );
                continue;
            }
            Err(None) => continue,
        }

        let asked = remaining.len();
        let (found, failed, error) = ask_all(&remaining, endpoint, &query).await;
        let answered = asked - failed.len();
        lock(book).finish(local, endpoint.host, answered > 0, Instant::now());
        log_round(origin, endpoint.host, asked, answered, error, now.elapsed());
        answers.extend(found);
        remaining = failed;
    }

    let now = Instant::now();
    let mut book = lock(book);
    for (host, name) in wanted {
        let lookup = match answers.get(&name) {
            Some(ips) if !ips.is_empty() => {
                book.remember(name, ips.clone(), now);
                Lookup::Found(ips.clone())
            }
            Some(_) => Lookup::NotFound,
            None => Lookup::Failed,
        };
        out.insert(host, lookup);
    }
    out
}

type Round = (HashMap<String, Vec<IpAddr>>, Vec<String>, Option<String>);

/// Все имена — одному резолверу, по `PARALLEL` сразу. Возвращает ответы, имена без
/// ответа и первую ошибку (для журнала).
async fn ask_all<Q, F>(names: &[String], endpoint: Endpoint, query: &Q) -> Round
where
    Q: Fn(Endpoint, String) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<Vec<IpAddr>, String>> + Send + 'static,
{
    let semaphore = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut set = JoinSet::new();
    for name in names {
        let (query, name, semaphore) = (query.clone(), name.clone(), Arc::clone(&semaphore));
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            let result = query(endpoint, name.clone()).await;
            (name, result)
        });
    }
    let mut unanswered: HashSet<String> = names.iter().cloned().collect();
    let mut found = HashMap::new();
    let mut error = None;
    while let Some(joined) = set.join_next().await {
        let Ok((name, result)) = joined else { continue };
        match result {
            Ok(ips) => {
                unanswered.remove(&name);
                found.insert(name, ips);
            }
            Err(e) => {
                error.get_or_insert(e);
            }
        }
    }
    // Порядок как в запросе: следующий резолвер получает их так же.
    let failed = names
        .iter()
        .filter(|n| unanswered.contains(*n))
        .cloned()
        .collect();
    (found, failed, error)
}

/// Одна запись на опрос резолвера, без самих имён: адреса серверов — секрет.
fn log_round(
    origin: Origin,
    host: &str,
    asked: usize,
    answered: usize,
    error: Option<String>,
    took: Duration,
) {
    let outcome = if answered > 0 {
        netlog::Outcome::Ok
    } else {
        netlog::Outcome::Failed
    };
    let mut detail = crate::trf!(
        "DoH: адреса серверов — {answered} из {asked}",
        "DoH: server addresses — {answered} of {asked}"
    );
    if let Some(e) = error.filter(|_| answered < asked) {
        detail = format!("{detail}; {e}");
    }
    netlog::record(
        netlog::Event::new(origin, Purpose::Dns, host, Route::Direct, outcome)
            .detail(detail)
            .ms(took),
    );
}

/// Клиент DoH на адрес источника `local`: имена резолверов привязаны к их IP,
/// системный прокси не используется.
fn client(local: Option<Ipv4Addr>) -> Result<reqwest::Client, String> {
    let mut clients = lock(&CLIENTS);
    if let Some(c) = clients.get(&local) {
        return Ok(c.clone());
    }
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .timeout(QUERY_TIMEOUT)
        .connect_timeout(QUERY_TIMEOUT)
        .pool_idle_timeout(POOL_IDLE)
        .local_address(local.map(IpAddr::V4));
    for doh in RESOLVERS.iter().filter_map(|r| r.doh) {
        builder = builder.resolve(doh.host, SocketAddr::from((doh.ip, 443)));
    }
    let client = builder.build().map_err(|e| e.to_string())?;
    // Адрес адаптера меняется со сменой сети — старые клиенты не копим.
    if clients.len() >= 4 {
        clients.clear();
    }
    clients.insert(local, client.clone());
    Ok(client)
}

/// Адреса имени: запись A, а если её нет — AAAA.
async fn ask(
    client: reqwest::Client,
    endpoint: Endpoint,
    name: String,
) -> Result<Vec<IpAddr>, String> {
    let a = post(&client, endpoint, &name, wire::TYPE_A).await?;
    match a.rcode {
        0 => {}
        wire::RCODE_NXDOMAIN => return Ok(Vec::new()),
        // SERVFAIL, REFUSED: этот резолвер не смог — спросим следующий.
        code => return Err(format!("rcode {code}")),
    }
    let ips = usable(a.a.into_iter().map(IpAddr::V4));
    if !ips.is_empty() {
        return Ok(ips);
    }
    let aaaa = post(&client, endpoint, &name, wire::TYPE_AAAA).await?;
    Ok(usable(aaaa.aaaa.into_iter().map(IpAddr::V6)))
}

async fn post(
    client: &reqwest::Client,
    endpoint: Endpoint,
    name: &str,
    qtype: u16,
) -> Result<wire::Answer, String> {
    // RFC 8484: в DoH id = 0, ответ привязан к HTTP-запросу.
    let q = wire::query(0, name, qtype).map_err(|e| e.to_string())?;
    let response = client
        .post(format!("https://{}/dns-query", endpoint.host))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(q)
        .send()
        .await
        .map_err(|e| describe(&e))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    let body = response.bytes().await.map_err(|e| describe(&e))?;
    wire::parse(&body, 0).map_err(|e| e.to_string())
}

fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() || e.is_connect() {
        crate::i18n::tr("нет ответа", "no response").into()
    } else {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor::NetPolicy;

    const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    /// Поддельный резолвер: кто и сколько раз спрошен, отвечают только `alive`.
    #[derive(Clone)]
    struct Fake {
        alive: &'static [&'static str],
        asked: Arc<Mutex<Vec<(&'static str, String)>>>,
    }

    impl Fake {
        fn new(alive: &'static [&'static str]) -> Self {
            Self {
                alive,
                asked: Arc::default(),
            }
        }

        fn query(
            &self,
        ) -> impl Fn(Endpoint, String) -> std::future::Ready<Result<Vec<IpAddr>, String>>
               + Clone
               + Send
               + Sync
               + 'static {
            let me = self.clone();
            move |endpoint: Endpoint, name: String| {
                lock(&me.asked).push((endpoint.host, name.clone()));
                std::future::ready(if !me.alive.contains(&endpoint.host) {
                    Err("нет ответа".into())
                } else if name.starts_with("nx.") {
                    Ok(Vec::new())
                } else {
                    Ok(vec![SERVER])
                })
            }
        }

        fn hosts_asked(&self) -> Vec<&'static str> {
            lock(&self.asked).iter().map(|(h, _)| *h).collect()
        }
    }

    fn governor() -> Mutex<NetGovernor> {
        Mutex::new(NetGovernor::new(NetPolicy::default()))
    }

    async fn run(
        book: &Mutex<Book>,
        gov: &Mutex<NetGovernor>,
        fake: &Fake,
        hosts: &[&str],
    ) -> HashMap<String, Lookup> {
        let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        let doh = Doh {
            first: "google",
            governor: gov,
        };
        resolve_with(book, None, &hosts, &doh, Origin::App, fake.query()).await
    }

    #[test]
    fn chosen_resolver_goes_first() {
        let hosts: Vec<&str> = order("quad9").iter().map(|e| e.host).collect();
        assert_eq!(hosts[0], "dns.quad9.net");
        assert_eq!(
            hosts.len(),
            RESOLVERS.iter().filter(|r| r.doh.is_some()).count()
        );
        // Незнакомый id — порядок каталога, без DoH-less Яндекса.
        assert_eq!(order("nope")[0].host, "cloudflare-dns.com");
    }

    #[tokio::test]
    async fn literals_and_bad_names_are_not_asked() {
        let fake = Fake::new(&["dns.google"]);
        let r = run(
            &Mutex::default(),
            &governor(),
            &fake,
            &["203.0.113.9", "[2001:db8::1]", "", "пример.рф", "a..b"],
        )
        .await;
        assert_eq!(
            r["203.0.113.9"],
            Lookup::Found(vec!["203.0.113.9".parse().unwrap()])
        );
        assert_eq!(
            r["[2001:db8::1]"],
            Lookup::Found(vec!["2001:db8::1".parse().unwrap()])
        );
        assert_eq!(r[""], Lookup::NotFound);
        assert_eq!(r["пример.рф"], Lookup::NotFound);
        assert_eq!(r["a..b"], Lookup::NotFound);
        assert!(fake.hosts_asked().is_empty());
    }

    #[tokio::test]
    async fn answered_by_chosen_resolver_only() {
        let fake = Fake::new(&["dns.google"]);
        let r = run(
            &Mutex::default(),
            &governor(),
            &fake,
            &["A.example.com.", "b.example.com", "nx.example.com"],
        )
        .await;
        assert_eq!(r["A.example.com."], Lookup::Found(vec![SERVER]));
        assert_eq!(r["nx.example.com"], Lookup::NotFound);
        assert_eq!(fake.hosts_asked(), ["dns.google"; 3]);
        // Имя спрошено в нижнем регистре и без точки в конце.
        assert!(lock(&fake.asked).iter().any(|(_, n)| n == "a.example.com"));
    }

    #[tokio::test]
    async fn falls_back_to_next_doh_and_skips_dead_one() {
        let book = Mutex::default();
        let gov = governor();
        let fake = Fake::new(&["cloudflare-dns.com"]);
        let r = run(&book, &gov, &fake, &["a.example.com"]).await;
        assert_eq!(r["a.example.com"], Lookup::Found(vec![SERVER]));
        assert_eq!(fake.hosts_asked(), ["dns.google", "cloudflare-dns.com"]);

        // Google минуту не спрашиваем — сразу Cloudflare.
        let fake = Fake::new(&["cloudflare-dns.com"]);
        run(&book, &gov, &fake, &["b.example.com"]).await;
        assert_eq!(fake.hosts_asked(), ["cloudflare-dns.com"]);
    }

    #[tokio::test]
    async fn no_doh_answers_means_failed_not_system_dns() {
        let fake = Fake::new(&[]);
        let r = run(&Mutex::default(), &governor(), &fake, &["a.example.com"]).await;
        assert_eq!(r["a.example.com"], Lookup::Failed);
        assert_eq!(fake.hosts_asked().len(), order("google").len());
    }

    #[tokio::test]
    async fn found_addresses_are_cached() {
        let book = Mutex::default();
        let gov = governor();
        let fake = Fake::new(&["dns.google"]);
        run(&book, &gov, &fake, &["a.example.com", "nx.example.com"]).await;
        let r = run(&book, &gov, &fake, &["A.EXAMPLE.COM", "nx.example.com"]).await;
        assert_eq!(r["A.EXAMPLE.COM"], Lookup::Found(vec![SERVER]));
        // Ненайденное не кэшируется: спрошено второй раз.
        assert_eq!(fake.hosts_asked().len(), 3);
    }

    #[tokio::test]
    async fn governor_limits_new_connections_not_queries() {
        let book = Mutex::default();
        let gov = governor();
        let fake = Fake::new(&["dns.google", "cloudflare-dns.com"]);
        // Соединение открыто — следующие опросы NetGovernor не трогают.
        for name in ["a.example.com", "b.example.com", "c.example.com"] {
            run(&book, &gov, &fake, &[name]).await;
        }
        assert_eq!(fake.hosts_asked(), ["dns.google"; 3]);

        // Новое соединение к Google NetGovernor не разрешил — спрашиваем Cloudflare.
        lock(&book).conns.clear();
        let fake = Fake::new(&["dns.google", "cloudflare-dns.com"]);
        let r = run(&book, &gov, &fake, &["d.example.com"]).await;
        assert_eq!(r["d.example.com"], Lookup::Found(vec![SERVER]));
        assert_eq!(fake.hosts_asked(), ["cloudflare-dns.com"]);
    }

    #[tokio::test]
    async fn duplicates_asked_once() {
        let fake = Fake::new(&["dns.google"]);
        let r = run(
            &Mutex::default(),
            &governor(),
            &fake,
            &["a.example.com", "A.example.com", "a.example.com"],
        )
        .await;
        assert_eq!(r.len(), 2);
        assert_eq!(fake.hosts_asked().len(), 1);
    }

    #[test]
    fn placeholder_addresses_are_dropped() {
        let ips = usable([
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "::".parse().unwrap(),
            "::1".parse().unwrap(),
            SERVER,
        ]);
        assert_eq!(ips, [SERVER]);
    }

    #[test]
    fn cache_is_bounded() {
        let mut book = Book::default();
        let now = Instant::now();
        for i in 0..=CACHE_MAX {
            book.remember(format!("s{i}.example.com"), vec![SERVER], now);
        }
        assert!(book.cache.len() <= CACHE_MAX);
    }

    /// Настоящий DoH: `cargo test -p kvt-core real_doh -- --ignored`. Нужна сеть.
    #[tokio::test]
    #[ignore]
    async fn real_doh() {
        let gov = governor();
        let doh = Doh {
            first: "cloudflare",
            governor: &gov,
        };
        let hosts = ["one.one.one.one".to_string(), "nx.kvt.invalid".to_string()];
        let r = resolve(&hosts, &doh, None, Origin::App).await;
        println!("{r:?}");
        assert!(matches!(&r["one.one.one.one"], Lookup::Found(ips) if !ips.is_empty()));
        assert_eq!(r["nx.kvt.invalid"], Lookup::NotFound);
    }
}
