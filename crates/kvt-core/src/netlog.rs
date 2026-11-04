//! Журнал сетевых запросов: каждое соединение, которое открывает KVT или служба.
//!
//! Нужен, чтобы пользователь видел, куда и зачем ходит программа, и что всплесков
//! соединений (на которые реагирует ТСПУ) нет. Журнал живёт только в памяти
//! процесса — последние [`CAPACITY`] записей — и на диск не пишется.
//!
//! В журнал попадает только хост: путь и параметры ссылки (в них токены подписок)
//! отбрасываются в [`host_of`], а пояснения обрезаются до [`MAX_DETAIL`] символов.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Сколько записей хранит каждый процесс.
pub const CAPACITY: usize = 1000;
/// Длина пояснения (текста ошибки) в символах.
pub const MAX_DETAIL: usize = 120;
const MAX_HOST: usize = 253;

/// Какой процесс открыл соединение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    App,
    Service,
}

/// Зачем.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Загрузка подписки.
    Subscription,
    /// Быстрая проверка сервера (только TCP, без TLS).
    ServerPing,
    /// Полная проверка сервера через тестовое ядро.
    ServerCheck,
    /// Проверка, что через туннель идут данные.
    Tunnel,
    /// Проверка DNS.
    Dns,
    /// Проверка доступности YouTube и Discord для zapret.
    Zapret,
    /// Списки маршрутизации (podkop, runetfreedom).
    Rules,
    /// Версии и комплекты: zapret Flowseal, позже — сам KVT.
    Update,
    /// Просит ли сеть войти (страница входа в отеле, кафе).
    Captive,
}

/// Каким путём шло соединение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// Напрямую через сеть провайдера (если VPN подключён — по правилам маршрутизации).
    Direct,
    /// Через VPN-туннель.
    Tunnel,
    /// Через временное тестовое ядро на локальном порту.
    TestCore,
}

/// Чем кончилось.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Failed,
    /// NetGovernor не дал открыть соединение сейчас — лимит запросов к этому хосту.
    Deferred,
    /// Хост заморожен провайдером — соединение не открывалось.
    Frozen,
}

impl Outcome {
    /// Соединение действительно открывалось (а не было остановлено NetGovernor).
    pub fn opened(self) -> bool {
        matches!(self, Outcome::Ok | Outcome::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// Unix-время в миллисекундах.
    pub at: u64,
    pub origin: Origin,
    pub purpose: Purpose,
    pub host: String,
    pub route: Route,
    pub outcome: Outcome,
    /// Длительность запроса, если он состоялся.
    pub ms: Option<u64>,
    /// Короткое пояснение без секретов: ошибка, протокол DNS и т. п.
    pub detail: String,
}

impl Event {
    pub fn new(
        origin: Origin,
        purpose: Purpose,
        host: &str,
        route: Route,
        outcome: Outcome,
    ) -> Self {
        Self {
            at: now_ms(),
            origin,
            purpose,
            host: clean_host(host),
            route,
            outcome,
            ms: None,
            detail: String::new(),
        }
    }

    pub fn ms(mut self, elapsed: Duration) -> Self {
        self.ms = Some(elapsed.as_millis() as u64);
        self
    }

    pub fn detail(mut self, detail: impl AsRef<str>) -> Self {
        self.detail = clip(detail.as_ref(), MAX_DETAIL);
        self
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Хост из ссылки: без схемы, пути, параметров и учётных данных.
/// Для строки, которая не разбирается как ссылка, — она сама после очистки.
pub fn host_of(url: &str) -> String {
    // Без схемы `host:port` разобрался бы как схема `host` — такое просто чистим.
    if !url.contains("://") {
        return clean_host(url);
    }
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(clean_host))
        .unwrap_or_default()
}

/// Оставляет только символы, допустимые в имени хоста, адресе и порте,
/// и обрезает всё, что идёт после первого `/`, `?` или `#`.
fn clean_host(raw: &str) -> String {
    let raw = raw.trim();
    let raw = raw.rsplit_once('@').map_or(raw, |(_, h)| h);
    let end = raw.find(['/', '?', '#']).unwrap_or(raw.len());
    raw[..end]
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
        .take(MAX_HOST)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn clip(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Записать, что NetGovernor не дал открыть соединение (`Allowed` не записывается:
/// само соединение запишет тот, кто его откроет).
pub fn record_hold(
    origin: Origin,
    purpose: Purpose,
    host: &str,
    route: Route,
    decision: &crate::governor::Decision,
) {
    use crate::governor::Decision;
    let now = std::time::Instant::now();
    let (outcome, until) = match decision {
        Decision::Allowed => return,
        Decision::RetryAt(at) => (Outcome::Deferred, *at),
        Decision::Frozen { until } => (Outcome::Frozen, *until),
    };
    let secs = until.saturating_duration_since(now).as_secs().max(1);
    record(
        Event::new(origin, purpose, host, route, outcome).detail(format!("повтор через {secs} с")),
    );
}

/// Кольцевой буфер последних событий.
#[derive(Debug, Default)]
pub struct NetLog {
    events: VecDeque<Event>,
}

impl NetLog {
    pub const fn new() -> Self {
        Self {
            events: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: Event) {
        if self.events.len() >= CAPACITY {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// События от старых к новым.
    pub fn events(&self) -> Vec<Event> {
        self.events.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

static LOG: Mutex<NetLog> = Mutex::new(NetLog::new());

/// Записать событие в журнал этого процесса.
pub fn record(event: Event) {
    if let Ok(mut log) = LOG.lock() {
        log.push(event);
    }
}

/// Все события этого процесса, от старых к новым.
pub fn snapshot() -> Vec<Event> {
    LOG.lock().map(|l| l.events()).unwrap_or_default()
}

pub fn clear() {
    if let Ok(mut log) = LOG.lock() {
        log.clear();
    }
}

/// Сводка по одному хосту.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSummary {
    pub host: String,
    /// Открытых соединений за окно.
    pub opened: usize,
    pub failed: usize,
    /// Сколько раз NetGovernor остановил запрос (лимит или заморозка).
    pub held: usize,
    /// Наибольшее число соединений за любую минуту окна — признак всплеска.
    pub peak_per_minute: usize,
    pub last: u64,
}

/// Сводка по хостам за последние `window` до момента `now` (мс), самые активные сверху.
pub fn summarize(events: &[Event], now: u64, window: Duration) -> Vec<HostSummary> {
    let since = now.saturating_sub(window.as_millis() as u64);
    let mut by_host: BTreeMap<&str, (HostSummary, Vec<u64>)> = BTreeMap::new();
    for e in events.iter().filter(|e| e.at >= since && e.at <= now) {
        let (s, times) = by_host.entry(e.host.as_str()).or_insert_with(|| {
            (
                HostSummary {
                    host: e.host.clone(),
                    opened: 0,
                    failed: 0,
                    held: 0,
                    peak_per_minute: 0,
                    last: 0,
                },
                Vec::new(),
            )
        });
        if e.outcome.opened() {
            s.opened += 1;
            times.push(e.at);
        } else {
            s.held += 1;
        }
        if e.outcome == Outcome::Failed {
            s.failed += 1;
        }
        s.last = s.last.max(e.at);
    }
    let mut out: Vec<HostSummary> = by_host
        .into_values()
        .map(|(mut s, mut times)| {
            times.sort_unstable();
            s.peak_per_minute = peak(&times, 60_000);
            s
        })
        .collect();
    out.sort_by(|a, b| {
        b.opened
            .cmp(&a.opened)
            .then(b.last.cmp(&a.last))
            .then(a.host.cmp(&b.host))
    });
    out
}

/// Наибольшее число отметок в любом окне длиной `span` мс (отметки отсортированы).
fn peak(times: &[u64], span: u64) -> usize {
    let mut best = 0;
    let mut start = 0;
    for (end, t) in times.iter().enumerate() {
        while *t - times[start] >= span {
            start += 1;
        }
        best = best.max(end - start + 1);
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(at: u64, host: &str, outcome: Outcome) -> Event {
        let mut e = Event::new(
            Origin::App,
            Purpose::Subscription,
            host,
            Route::Direct,
            outcome,
        );
        e.at = at;
        e
    }

    #[test]
    fn host_of_drops_path_query_and_credentials() {
        assert_eq!(
            host_of("https://sub.example.com/api/SECRET?token=abc"),
            "sub.example.com"
        );
        assert_eq!(
            host_of("https://user:pass@Sub.Example.com:8443/x"),
            "sub.example.com"
        );
        assert_eq!(host_of("1.1.1.1:53"), "1.1.1.1:53");
        assert_eq!(host_of("weird host/SECRET"), "weirdhost");
        assert_eq!(host_of(""), "");
    }

    #[test]
    fn event_host_never_keeps_path() {
        let e = Event::new(
            Origin::App,
            Purpose::Subscription,
            "sub.example.com/SECRET-TOKEN",
            Route::Direct,
            Outcome::Ok,
        );
        assert_eq!(e.host, "sub.example.com");
    }

    #[test]
    fn detail_is_clipped() {
        let e = ev(0, "a.com", Outcome::Failed).detail("я".repeat(500));
        assert_eq!(e.detail.chars().count(), MAX_DETAIL);
        assert!(e.detail.ends_with('…'));
    }

    #[test]
    fn ring_keeps_last_entries() {
        let mut log = NetLog::new();
        for i in 0..(CAPACITY as u64 + 10) {
            log.push(ev(i, "a.com", Outcome::Ok));
        }
        let events = log.events();
        assert_eq!(events.len(), CAPACITY);
        assert_eq!(events[0].at, 10);
    }

    #[test]
    fn summary_counts_and_finds_peak() {
        let min = 60_000;
        let events = vec![
            ev(0, "a.com", Outcome::Ok),
            ev(1_000, "a.com", Outcome::Ok),
            ev(2_000, "a.com", Outcome::Failed),
            ev(3_000, "a.com", Outcome::Deferred),
            ev(5 * min, "a.com", Outcome::Ok),
            ev(5 * min, "b.com", Outcome::Ok),
        ];
        let s = summarize(&events, 5 * min, Duration::from_secs(3600));
        assert_eq!(s[0].host, "a.com");
        assert_eq!(s[0].opened, 4);
        assert_eq!(s[0].failed, 1);
        assert_eq!(s[0].held, 1);
        assert_eq!(s[0].peak_per_minute, 3);
        assert_eq!(s[0].last, 5 * min);
        assert_eq!(s[1].host, "b.com");
        assert_eq!(s[1].peak_per_minute, 1);
    }

    #[test]
    fn summary_respects_window() {
        let events = vec![
            ev(0, "old.com", Outcome::Ok),
            ev(10_000_000, "new.com", Outcome::Ok),
        ];
        let s = summarize(&events, 10_000_000, Duration::from_secs(3600));
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].host, "new.com");
    }

    #[test]
    fn peak_window_is_half_open() {
        assert_eq!(peak(&[0, 59_999, 60_000, 119_999], 60_000), 2);
        assert_eq!(peak(&[], 60_000), 0);
    }
}
