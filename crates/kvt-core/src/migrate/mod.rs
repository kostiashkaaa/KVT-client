//! Перенос подписок и ключей из других клиентов: v2rayN, Throne, NekoRay, Hiddify.
//!
//! Данные чужих клиентов только читаются. Здесь — преобразование их записей
//! (строка базы v2rayN, профиль NekoRay, исходящий sing-box из Throne и Hiddify)
//! в обычные ссылки `vless://`, `trojan://`, `ss://`, `hysteria2://`. Каждая
//! ссылка затем проходит тот же разбор, что и ссылка из подписки ([`crate::parser`]),
//! так что перенос не добавляет новых путей для непроверенных данных.
//!
//! Серверы из подписок не переносятся по одному: переносится ссылка подписки, а
//! серверы KVT загрузит сам — так они будут обновляться.
//!
//! Состав: здесь — типы собранного и предпросмотр; `link` собирает ссылку, а
//! `v2rayn`, `nekoray` и `singbox` читают профили своих клиентов.

use crate::i18n::tr;
use crate::parser::{parse_uri, Entry};
use crate::Secret;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Client {
    V2rayN,
    Throne,
    NekoRay,
    Hiddify,
    Happ,
}

impl Client {
    pub fn title(self) -> &'static str {
        match self {
            Client::V2rayN => "v2rayN",
            Client::Throne => "Throne",
            Client::NekoRay => "NekoRay",
            Client::Hiddify => "Hiddify",
            Client::Happ => "Happ",
        }
    }
}

/// Подписка другого клиента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub name: String,
    pub url: Secret,
}

/// Сервер, добавленный в другом клиенте вручную, уже в виде ссылки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    pub protocol: String,
    pub link: Secret,
}

/// Всё, что нашлось в одном клиенте. Ссылки — секреты и в интерфейс не уходят.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collected {
    pub client: Client,
    /// Где лежат данные (каталог), для показа пользователю.
    pub location: String,
    pub subscriptions: Vec<Subscription>,
    pub servers: Vec<Server>,
    /// Причины, по которым записи не перенесены (по одной на запись).
    pub skipped: Vec<&'static str>,
    /// Пояснение, если перенести ничего нельзя (например, данные зашифрованы).
    pub note: Option<String>,
}

impl Collected {
    pub fn new(client: Client, location: impl Into<String>) -> Self {
        Self {
            client,
            location: location.into(),
            subscriptions: Vec::new(),
            servers: Vec::new(),
            skipped: Vec::new(),
            note: None,
        }
    }

    /// Подписка по ссылке; `http://` и мусор пропускаются, повторы — тоже.
    pub fn add_subscription(&mut self, name: &str, url: &str) {
        match subscription_url(url) {
            Ok(url) => {
                if !self.subscriptions.iter().any(|s| s.url.expose() == url) {
                    self.subscriptions.push(Subscription {
                        name: clean_name(name),
                        url: Secret::new(url),
                    });
                }
            }
            Err(reason) => self.skipped.push(reason),
        }
    }

    /// Сервер из уже собранной ссылки (или причина, почему её не собрать).
    pub fn add_server(&mut self, name: &str, link: Result<String, &'static str>) {
        match link.and_then(|l| check_link(&l).map(|protocol| (l, protocol))) {
            Ok((link, protocol)) => {
                if !self.servers.iter().any(|s| s.link.expose() == link) {
                    self.servers.push(Server {
                        name: clean_name(name),
                        protocol,
                        link: Secret::new(link),
                    });
                }
            }
            Err(reason) => self.skipped.push(reason),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty() && self.servers.is_empty()
    }

    /// Что показать пользователю перед переносом: без ссылок и ключей.
    pub fn preview(&self) -> Preview {
        let mut skipped: Vec<(&'static str, usize)> = Vec::new();
        for r in &self.skipped {
            match skipped.iter_mut().find(|(s, _)| s == r) {
                Some((_, n)) => *n += 1,
                None => skipped.push((r, 1)),
            }
        }
        Preview {
            client: self.client,
            title: self.client.title(),
            location: self.location.clone(),
            subscriptions: self
                .subscriptions
                .iter()
                .map(|s| PreviewSubscription {
                    name: s.name.clone(),
                    host: crate::netlog::host_of(s.url.expose()),
                })
                .collect(),
            servers: self
                .servers
                .iter()
                .map(|s| PreviewServer {
                    name: s.name.clone(),
                    protocol: s.protocol.clone(),
                })
                .collect(),
            skipped: skipped
                .into_iter()
                .map(|(reason, count)| Skipped { reason, count })
                .collect(),
            note: self.note.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub client: Client,
    pub title: &'static str,
    pub location: String,
    pub subscriptions: Vec<PreviewSubscription>,
    pub servers: Vec<PreviewServer>,
    pub skipped: Vec<Skipped>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewSubscription {
    pub name: String,
    /// Только адрес сервера подписки: в пути ссылки — токен.
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewServer {
    pub name: String,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub reason: &'static str,
    pub count: usize,
}

const MAX_NAME: usize = 120;

fn clean_name(name: &str) -> String {
    let n: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect();
    let n = n.trim();
    if n.is_empty() {
        tr("Без названия", "Untitled").into()
    } else {
        n.to_owned()
    }
}

fn subscription_url(raw: &str) -> Result<String, &'static str> {
    let raw = raw.trim();
    let url = url::Url::parse(raw)
        .map_err(|_| tr("повреждённая ссылка подписки", "broken subscription link"))?;
    match url.scheme() {
        "https" if url.host_str().is_some() => Ok(raw.to_owned()),
        "http" => Err(tr(
            "подписка по незащищённому http",
            "subscription over insecure http",
        )),
        _ => Err(tr(
            "повреждённая ссылка подписки",
            "broken subscription link",
        )),
    }
}

/// Ссылка разбирается тем же парсером, что и подписки. Возвращает протокол.
fn check_link(link: &str) -> Result<String, &'static str> {
    match parse_uri(link) {
        Ok(Entry::Server(_)) => Ok(protocol_title(link)),
        Ok(Entry::Info(_)) => Err(tr(
            "служебная запись провайдера",
            "provider's service entry",
        )),
        Err(crate::parser::ParseError::Unsupported(_)) => Err(tr(
            "протокол или настройка не поддерживается",
            "protocol or setting not supported",
        )),
        Err(_) => Err(tr(
            "неполные или повреждённые данные сервера",
            "incomplete or broken server data",
        )),
    }
}

fn protocol_title(link: &str) -> String {
    match link.split_once("://").map(|(s, _)| s) {
        Some("vless") => "VLESS",
        Some("trojan") => "Trojan",
        Some("ss") => "Shadowsocks",
        Some("hysteria2" | "hy2") => "Hysteria2",
        _ => "?",
    }
    .into()
}

mod link;
mod nekoray;
mod singbox;
#[cfg(test)]
mod tests;
mod v2rayn;

pub use nekoray::nekoray_profile;
pub use singbox::{is_service_outbound, singbox_config, singbox_outbound};
pub use v2rayn::v2rayn_profile;
