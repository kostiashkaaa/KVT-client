//! Словарь проверки DNS: что наблюдалось ([`Observations`]) и что из этого вывели
//! ([`DnsReport`]). Данные без поведения; выводы делает `analyze`.

use super::resolvers::ser_title;
use super::Answer;
use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Udp,
    Dot,
    Doh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    Answer { answer: Answer, ms: u64 },
    Timeout,
    Failed(String),
}

impl QueryResult {
    pub(super) fn answer(&self) -> Option<&Answer> {
        match self {
            QueryResult::Answer { answer, .. } => Some(answer),
            _ => None,
        }
    }

    /// Адрес из ответа на `whoami.akamai.net`.
    pub(super) fn egress(&self) -> Option<Ipv4Addr> {
        self.answer().and_then(|a| a.a.first().copied())
    }
}

/// Кого спрашивали: DNS из настроек сети или резолвер из каталога.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    System,
    Resolver(&'static str, Via),
}

#[derive(Debug, Clone, Default)]
pub struct Observations {
    /// DNS-сервер из настроек сети (обычно роутер или провайдер).
    pub system_server: Option<Ipv4Addr>,
    /// `whoami.akamai.net` через DNS из настроек сети.
    pub system_whoami: Option<QueryResult>,
    /// `whoami.akamai.net`: каждый резолвер каждым способом.
    pub whoami: Vec<(&'static str, Via, QueryResult)>,
    /// Домены из [`SPOOF_DOMAINS`].
    pub spoof: Vec<(&'static str, Source, QueryResult)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PathStatus {
    Works {
        ms: u64,
    },
    /// Отвечает не тот, кого спрашивали: провайдер перехватывает запросы.
    Intercepted {
        ms: u64,
        by: Ipv4Addr,
    },
    /// Нет ответа — скорее всего, порт или адрес заблокирован.
    Blocked,
    Failed {
        reason: String,
    },
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolverReport {
    pub id: &'static str,
    #[serde(serialize_with = "ser_title")]
    pub title: &'static str,
    pub udp: PathStatus,
    pub dot: PathStatus,
    pub doh: PathStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpoofKind {
    /// Адрес из частной сети или один адрес для разных сайтов — страница блокировки.
    Stub,
    /// Адрес FakeIP (198.18.0.0/15): роутер сам ведёт сайт через свой VPN.
    FakeIp,
    /// «Такого сайта нет» или отказ, хотя зашифрованный DNS его находит.
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpoofFinding {
    pub domain: &'static str,
    /// Кто подменил: «DNS сети» или «Google (UDP)».
    pub source: String,
    pub kind: SpoofKind,
    pub got: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Ok,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsReport {
    pub resolvers: Vec<ResolverReport>,
    pub system_server: Option<Ipv4Addr>,
    /// Резолвер, который на самом деле обслуживает DNS из настроек сети.
    pub system_egress: Option<Ipv4Addr>,
    pub interception: bool,
    /// Подмена провайдером (без FakeIP роутера).
    pub spoofing: Vec<SpoofFinding>,
    /// DNS сети отдаёт адреса FakeIP: на роутере работает podkop или похожий обход.
    pub fake_ip: bool,
    /// Хотя бы один зашифрованный DNS (DoH/DoT) работает напрямую.
    pub encrypted_available: bool,
    /// Резолвер для прямых сайтов (id из [`RESOLVERS`]).
    pub recommended_local: &'static str,
    pub tone: Tone,
    pub title: String,
    pub detail: String,
}
