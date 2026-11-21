//! Сервисы на вкладке «Проверка» («работает ли то, что мне надо»): данные из
//! `presets/services.json`, путь трафика сервиса по плану маршрутизации и вердикт
//! пробы. Сами запросы шлёт окно (`services` в `kvt-app`) — здесь только логика без
//! сети, чтобы её проверяли тесты.
//!
//! Состав: здесь — данные и путь; `verdict` — что считать «работает», «медленно»,
//! «не работает» по итогам запроса.

use crate::routing::{Action, RoutingPlan};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

mod verdict;
pub use verdict::{classify, worst, Cause, Health, Sample, SAMPLE_BYTES};

#[cfg(test)]
mod tests;

const SERVICES_JSON: &str = include_str!("../../../../presets/services.json");

/// Сколько сервисов и адресов проб допускает файл данных: каждый адрес — отдельное
/// соединение под лимитами NetGovernor.
const MAX_SERVICES: usize = 16;
const MAX_PROBES: usize = 4;
const MAX_SETS: usize = 8;

/// Режим подключения, как в настройках окна (`mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Vpn,
    Hybrid,
    Zapret,
}

impl Mode {
    /// Неизвестное и пустое значение — «VPN», как при построении плана подключения.
    pub fn parse(mode: Option<&str>) -> Mode {
        match mode {
            Some("hybrid") => Mode::Hybrid,
            Some("zapret") => Mode::Zapret,
            _ => Mode::Vpn,
        }
    }
}

/// Адрес пробы: только HTTPS, без порта и логина, имя — обычный домен (оно же уходит
/// в SNI и в `NetGovernor`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Probe {
    pub url: String,
    /// Имя хоста в нижнем регистре.
    pub host: String,
}

impl TryFrom<String> for Probe {
    type Error = String;

    fn try_from(url: String) -> Result<Self, String> {
        let bad = || format!("адрес пробы «{url}» не годится: нужен https://домен/путь");
        let parsed = url::Url::parse(&url).map_err(|_| bad())?;
        if parsed.scheme() != "https"
            || parsed.port().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(bad());
        }
        let host = match parsed.host() {
            Some(url::Host::Domain(d)) if crate::zapret::valid_domain(d) => d.to_ascii_lowercase(),
            _ => return Err(bad()),
        };
        Ok(Probe { url, host })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServiceDef {
    pub id: String,
    pub name: String,
    /// Что запрашивать. По первому адресу определяется путь трафика.
    pub probes: Vec<Probe>,
    /// Наборы правил (`itdog:…`, `rf:…`), в которые входит сервис.
    #[serde(default)]
    pub sets: Vec<String>,
    /// В каких режимах сервис показан по умолчанию.
    pub modes: Vec<Mode>,
    /// В режиме «Zapret» его обрабатывают списки Flowseal.
    #[serde(default)]
    pub zapret: bool,
    /// Ходит через прокси Telegram (tg-ws-proxy), когда тот включён.
    #[serde(default)]
    pub telegram: bool,
}

impl ServiceDef {
    /// Хост, по которому определяется путь: первый адрес пробы.
    pub fn host(&self) -> &str {
        self.probes.first().map_or("", |p| p.host.as_str())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ServicesError {
    #[error("файл сервисов не разобрался: {0}")]
    Json(String),
    #[error("сервис «{id}»: {why}")]
    Invalid { id: String, why: &'static str },
    #[error("сервисов больше {MAX_SERVICES}")]
    TooMany,
}

#[derive(Deserialize)]
struct File {
    services: Vec<ServiceDef>,
}

/// Разбор и проверка файла данных. Файл поставляется с программой, но проверяется
/// как чужой: каждый адрес — исходящее соединение.
pub fn parse(json: &str) -> Result<Vec<ServiceDef>, ServicesError> {
    let file: File = serde_json::from_str(json).map_err(|e| ServicesError::Json(e.to_string()))?;
    if file.services.len() > MAX_SERVICES {
        return Err(ServicesError::TooMany);
    }
    let mut seen: Vec<&str> = Vec::new();
    for s in &file.services {
        let invalid = |why| ServicesError::Invalid {
            id: s.id.clone(),
            why,
        };
        if s.id.is_empty()
            || s.id.len() > 32
            || !s
                .id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
        {
            return Err(invalid("id — латиница, цифры, «_» и «-» (до 32 знаков)"));
        }
        if seen.contains(&s.id.as_str()) {
            return Err(invalid("id повторяется"));
        }
        seen.push(&s.id);
        if s.name.trim().is_empty() || s.name.chars().count() > 40 {
            return Err(invalid("название пустое или длиннее 40 знаков"));
        }
        if s.probes.is_empty() || s.probes.len() > MAX_PROBES {
            return Err(invalid("адресов пробы должно быть от 1 до 4"));
        }
        if s.sets.len() > MAX_SETS
            || s.sets
                .iter()
                .any(|name| crate::lists::RuleSetRef::parse(name).is_none())
        {
            return Err(invalid("неизвестный набор правил"));
        }
        if s.modes.is_empty() {
            return Err(invalid("не указан ни один режим"));
        }
    }
    Ok(file.services)
}

/// Сервисы из файла данных (разбираются один раз). Испорченный файл даёт пустой
/// список, а не падение; от этого защищает тест `bundled_file_is_valid`.
pub fn all() -> &'static [ServiceDef] {
    static SERVICES: OnceLock<Vec<ServiceDef>> = OnceLock::new();
    SERVICES.get_or_init(|| parse(SERVICES_JSON).unwrap_or_default())
}

/// Набор по умолчанию для режима.
pub fn for_mode(mode: Mode) -> impl Iterator<Item = &'static ServiceDef> {
    all().iter().filter(move |s| s.modes.contains(&mode))
}

/// Какие сервисы показывать: `picked` — свой набор пользователя (id), `None` — набор
/// по умолчанию. Свой набор уже режима: сервис, который в этом режиме не открыть
/// (Instagram и ChatGPT без VPN), не показывается, чтобы плитка не краснела зря.
/// Порядок — как в файле данных. Неизвестные id отбрасываются; если ничего не
/// осталось (файл данных поменялся, режим другой), берётся набор по умолчанию.
pub fn select(mode: Mode, picked: Option<&[String]>) -> Vec<&'static ServiceDef> {
    let chosen: Vec<&ServiceDef> = match picked {
        Some(ids) => for_mode(mode).filter(|s| ids.contains(&s.id)).collect(),
        None => Vec::new(),
    };
    if chosen.is_empty() {
        for_mode(mode).collect()
    } else {
        chosen
    }
}

/// Оставляет в своём наборе только известные сервисы (без повторов), в порядке файла
/// данных. Пусто или отмечено всё — `None`: набор по умолчанию (иначе после «вернул все
/// отметки» в окне осталось бы «свой набор», который ничем не отличается).
pub fn clean_picked(ids: &[String]) -> Option<Vec<String>> {
    let kept: Vec<String> = all()
        .iter()
        .filter(|s| ids.contains(&s.id))
        .map(|s| s.id.clone())
        .collect();
    (!kept.is_empty() && kept.len() < all().len()).then_some(kept)
}

/// Каким путём идёт трафик сервиса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Vpn,
    Zapret,
    Direct,
    /// Прокси Telegram (tg-ws-proxy).
    Proxy,
    /// Правилами маршрутизации сервис закрыт.
    Blocked,
}

/// Что сейчас работает на самом деле. Не выбранный режим: пока не подключено,
/// трафик идёт мимо всего, что настроено, и подпись должна это показывать.
pub enum Running<'a> {
    Off,
    /// VPN или «Гибрид»; `plan` — тот, с которым подключались (с правилами zapret
    /// в «Гибриде» и прокси Telegram), а не тот, что собрался бы из выбора сейчас.
    Vpn {
        plan: &'a RoutingPlan,
    },
    /// Только zapret, без VPN и без плана маршрутизации.
    Zapret,
}

/// Путь трафика сервиса. `telegram_proxy` — прокси Telegram включён в настройках: он
/// работает при любом подключении (VPN, «Гибрид», «Zapret»), и Telegram Desktop по
/// замыслу KVT всегда подключён к нему — меняется только путь самого прокси
/// (`tgproxy::route_rules`), а проба Telegram идёт по тому же пути, что и он.
pub fn via(def: &ServiceDef, running: &Running<'_>, telegram_proxy: bool) -> Via {
    let proxied = def.telegram && telegram_proxy;
    match running {
        Running::Off => Via::Direct,
        Running::Zapret if proxied => Via::Proxy,
        Running::Zapret if def.zapret => Via::Zapret,
        Running::Zapret => Via::Direct,
        Running::Vpn { .. } if proxied => Via::Proxy,
        Running::Vpn { plan } => {
            let action = plan.resolve_host(def.host(), |set| def.sets.iter().any(|s| s == set));
            match action {
                Action::Proxy => Via::Vpn,
                Action::Direct => Via::Direct,
                Action::Zapret => Via::Zapret,
                Action::Block => Via::Blocked,
            }
        }
    }
}
