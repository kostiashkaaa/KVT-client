//! RoutingPlan — единый источник правды для маршрутизации. Из него собираются
//! правила ядра (Xray / sing-box) и списки zapret, поэтому VPN и zapret не могут
//! обрабатывать один и тот же трафик.
//!
//! Состав: типы, проверка и разрешение доменов — здесь; готовые наборы правил и
//! настройки маршрутизации пользователя — в `presets`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Proxy,
    Direct,
    /// Трафик идёт напрямую, а winws обрабатывает его по hostlist.
    Zapret,
    Block,
}

/// Слои в порядке убывания приоритета.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// LAN и адреса VPN-серверов (защита от петель).
    System,
    User,
    Zapret,
    /// Пресет «Россия».
    Preset,
    /// Правила из подписки. По умолчанию выключены.
    Provider,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Matcher {
    /// Домен и все его поддомены.
    DomainSuffix(String),
    /// Ровно этот домен, без поддоменов.
    Domain(String),
    DomainKeyword(String),
    IpCidr(String),
    /// Набор правил из каталога `lists`: `itdog:<id>` или `rf:<имя>`.
    RuleSet(String),
    ProcessName(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub layer: Layer,
    pub matcher: Matcher,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPlan {
    rules: Vec<Rule>,
    pub final_action: Action,
    /// Адреса VPN-серверов: всегда Direct и всегда исключаются из zapret.
    server_addresses: Vec<String>,
}

/// Адрес проверки связи через туннель: ответ меньше 200 байт, в нём страна выхода.
/// Обычный HTTP — запрос идёт внутри туннеля, снаружи виден только VPN.
pub const HEALTH_URL: &str = "http://www.cloudflare.com/cdn-cgi/trace";
pub const HEALTH_HOST: &str = "www.cloudflare.com";

/// Источники «Проверить VPN»: `(адрес, подпись)` по порядку, пока один не
/// ответит. Cloudflare может быть недоступен из России — у каждого назначения
/// есть запасные: sypexgeo — российский сервис (ближе всех к «напрямую» из
/// России), ipwho.is — HTTPS. Ответ каждого разбирается отдельно (`vpncheck`).
pub const TRACE_URLS: &[(&str, &str)] = &[
    ("http://www.cloudflare.com/cdn-cgi/trace", "cloudflare"),
    ("http://api.sypexgeo.net/", "sypexgeo"),
    ("https://ipwho.is/", "ipwho.is"),
];

/// Замер скорости: читаем до конца окна (5 с), размер файла больше окна.
/// Запасной — файл OVH: проверить его доступность из России вживую; если не
/// отвечает, скорость просто «не измерилась», проверка от этого не ломается.
pub const SPEED_URLS: &[(&str, &str)] = &[
    (
        "http://speed.cloudflare.com/__down?bytes=4000000",
        "cloudflare",
    ),
    ("http://proof.ovh.net/files/10Mb.dat", "ovh"),
];

/// Имена источников «Проверить VPN» — их ведёт через VPN системное правило
/// (`with_health_check`): иначе при «остальное напрямую» пробы шли бы мимо
/// туннеля, и «через VPN» показывал бы домашний адрес.
pub const PROBE_HOSTS: &[&str] = &[
    "www.cloudflare.com",
    "speed.cloudflare.com",
    "api.sypexgeo.net",
    "ipwho.is",
    "proof.ovh.net",
];

/// Откуда KVT и служба скачивают списки и комплект zapret.
pub const UPDATE_HOSTS: &[&str] = &[
    "api.github.com",
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("{}", crate::trf!("адрес VPN-сервера «{}» попал под zapret", "VPN server address “{}” falls under zapret", .0))]
    ServerUnderZapret(String),
    #[error(
        "{}",
        crate::i18n::tr(
            "правила подписки не могут включать zapret",
            "subscription rules can't enable zapret"
        )
    )]
    ProviderZapret,
    #[error(
        "{}",
        crate::i18n::tr(
            "правило zapret должно задаваться доменом",
            "a zapret rule must be a domain"
        )
    )]
    ZapretNeedsDomain,
    /// Имя набора превращается в путь к файлу, поэтому неизвестные имена отвергаются.
    #[error("{}", crate::trf!("неизвестный набор правил «{}»", "unknown rule set “{}”", .0))]
    UnknownRuleSet(String),
    /// Строка правила уходит в конфиг ядра как есть: в ней не должно быть префиксов
    /// ядра (`regexp:`, `ext:…`), путей и управляющих символов.
    #[error("{}", crate::trf!("недопустимое правило «{}»", "invalid rule “{}”", .0))]
    InvalidMatcher(String),
}

/// Имя хоста или его часть для `domain`/`keyword`: буквы, цифры, `-`, `_`, точки
/// между частями. Кириллица к этому времени уже в punycode.
fn valid_host(s: &str, keyword: bool) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && (keyword || (!s.starts_with('.') && !s.ends_with('.') && !s.contains("..")))
}

/// IP или подсеть: `1.2.3.4`, `10.0.0.0/8`, `fe80::/10`.
fn valid_cidr(s: &str) -> bool {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (s, None),
    };
    let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|p| p <= max))
}

/// Имя программы (`telegram.exe`), а не путь.
fn valid_process(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.chars().any(|c| {
            c.is_control() || matches!(c, '\\' | '/' | ':' | '"' | '*' | '?' | '<' | '>' | '|')
        })
}

impl Matcher {
    fn is_valid(&self) -> bool {
        match self {
            Matcher::DomainSuffix(d) | Matcher::Domain(d) => valid_host(d, false),
            Matcher::DomainKeyword(k) => valid_host(k, true),
            Matcher::IpCidr(c) => valid_cidr(c),
            // Имена наборов проверяются отдельно (`UnknownRuleSet`).
            Matcher::RuleSet(_) => true,
            Matcher::ProcessName(p) => valid_process(p),
        }
    }
}

impl RoutingPlan {
    pub fn new(final_action: Action) -> Self {
        Self {
            rules: Vec::new(),
            final_action,
            server_addresses: Vec::new(),
        }
    }

    pub fn with_servers(mut self, addresses: impl IntoIterator<Item = String>) -> Self {
        for addr in addresses {
            let addr = addr.to_ascii_lowercase();
            let matcher = if addr.parse::<std::net::IpAddr>().is_ok() {
                Matcher::IpCidr(addr.clone())
            } else {
                Matcher::DomainSuffix(addr.clone())
            };
            self.rules.push(Rule {
                layer: Layer::System,
                matcher,
                action: Action::Direct,
            });
            self.server_addresses.push(addr);
        }
        self
    }

    /// Проверка связи через туннель и «Проверить VPN» (адрес выхода и скорость)
    /// всегда идут через VPN, в любом режиме маршрутизации: иначе при «остальном
    /// напрямую» они проверяли бы не туннель.
    pub fn with_health_check(mut self) -> Self {
        for host in PROBE_HOSTS {
            // Область проверки туннеля оставлена суффиксом, как была; остальные
            // имена — точные, чтобы не тащить за VPN чужие поддомены.
            let matcher = if *host == HEALTH_HOST {
                Matcher::DomainSuffix((*host).into())
            } else {
                Matcher::Domain((*host).into())
            };
            self.rules.push(Rule {
                layer: Layer::System,
                matcher,
                action: Action::Proxy,
            });
        }
        self
    }

    /// Загрузки KVT с GitHub (списки маршрутизации, комплект Flowseal) при
    /// подключённом VPN идут через туннель, если напрямую не вышло: у части
    /// провайдеров эти адреса тормозят. Только точные имена — остальной GitHub
    /// маршрутизируется как обычно.
    pub fn with_update_hosts(mut self) -> Self {
        for host in UPDATE_HOSTS {
            self.rules.push(Rule {
                layer: Layer::System,
                matcher: Matcher::Domain((*host).into()),
                action: Action::Proxy,
            });
        }
        self
    }

    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn extend(&mut self, rules: impl IntoIterator<Item = Rule>) {
        self.rules.extend(rules);
    }

    /// Правила в порядке применения: по слою, внутри слоя — в порядке добавления.
    pub fn ordered(&self) -> Vec<&Rule> {
        let mut rules: Vec<&Rule> = self.rules.iter().collect();
        rules.sort_by_key(|r| r.layer);
        rules
    }

    /// Действие для домена с учётом только доменных правил. Нужно для
    /// диагностики («куда пойдёт youtube.com?») и для тестов инвариантов.
    pub fn resolve_domain(&self, domain: &str) -> Action {
        self.resolve_host(domain, |_| false)
    }

    /// То же, но с наборами правил: `in_set(имя)` отвечает, входит ли домен в набор
    /// (`itdog:youtube`, `rf:ru-blocked`). Сами наборы — бинарные файлы ядер, здесь их
    /// не прочитать, поэтому членство задаёт вызывающий (для сервисов на главной —
    /// `presets/services.json`). Без этого «только заблокированное» показало бы
    /// YouTube напрямую, хотя он идёт через VPN по набору `russia_inside`, а выбор
    /// пользователя «YouTube напрямую» (тоже набор) был бы не виден.
    pub fn resolve_host(&self, domain: &str, in_set: impl Fn(&str) -> bool) -> Action {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.ordered()
            .into_iter()
            .find(|r| match &r.matcher {
                Matcher::DomainSuffix(s) => domain == *s || domain.ends_with(&format!(".{s}")),
                Matcher::Domain(d) => domain == *d,
                Matcher::DomainKeyword(k) => domain.contains(k.as_str()),
                Matcher::RuleSet(name) => in_set(name),
                _ => false,
            })
            .map(|r| r.action)
            .unwrap_or(self.final_action)
    }

    /// Hostlist для winws: домены, которые идут через zapret и не перекрыты
    /// правилами с более высоким приоритетом.
    pub fn zapret_hostlist(&self) -> Vec<String> {
        self.rules
            .iter()
            .filter(|r| r.action == Action::Zapret)
            .filter_map(|r| match &r.matcher {
                Matcher::DomainSuffix(d) => Some(d.clone()),
                _ => None,
            })
            .filter(|d| self.resolve_domain(d) == Action::Zapret)
            .collect()
    }

    /// Адреса, которые winws обязан исключить (`--ipset-exclude`).
    pub fn zapret_exclusions(&self) -> &[String] {
        &self.server_addresses
    }

    /// Имена наборов правил в порядке первого появления.
    pub fn rule_sets(&self) -> Vec<&str> {
        let mut names: Vec<&str> = Vec::new();
        for rule in self.ordered() {
            if let Matcher::RuleSet(name) = &rule.matcher {
                if !names.contains(&name.as_str()) {
                    names.push(name);
                }
            }
        }
        names
    }

    pub fn validate(&self) -> Result<(), RoutingError> {
        for name in self.rule_sets() {
            if crate::lists::RuleSetRef::parse(name).is_none() {
                return Err(RoutingError::UnknownRuleSet(name.to_owned()));
            }
        }
        // Служба не доверяет окну: строки правил проверяются здесь, а не только при вводе.
        if let Some(rule) = self.rules.iter().find(|r| !r.matcher.is_valid()) {
            return Err(RoutingError::InvalidMatcher(format!("{:?}", rule.matcher)));
        }
        for rule in &self.rules {
            if rule.action != Action::Zapret {
                continue;
            }
            if rule.layer == Layer::Provider {
                return Err(RoutingError::ProviderZapret);
            }
            if !matches!(rule.matcher, Matcher::DomainSuffix(_)) {
                return Err(RoutingError::ZapretNeedsDomain);
            }
        }
        for addr in &self.server_addresses {
            if self.resolve_domain(addr) == Action::Zapret {
                return Err(RoutingError::ServerUnderZapret(addr.clone()));
            }
        }
        Ok(())
    }
}

pub mod presets;

#[cfg(test)]
mod tests;
