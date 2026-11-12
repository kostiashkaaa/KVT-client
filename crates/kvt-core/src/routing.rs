//! RoutingPlan — единый источник правды для маршрутизации. Из него собираются
//! правила ядра (Xray / sing-box) и списки zapret, поэтому VPN и zapret не могут
//! обрабатывать один и тот же трафик.

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
    prefix.map_or(true, |p| p.parse::<u8>().is_ok_and(|p| p <= max))
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

    /// Проверка связи через туннель всегда идёт через VPN, в любом режиме
    /// маршрутизации: иначе при «остальное напрямую» она проверяла бы не туннель.
    pub fn with_health_check(mut self) -> Self {
        self.rules.push(Rule {
            layer: Layer::System,
            matcher: Matcher::DomainSuffix(HEALTH_HOST.into()),
            action: Action::Proxy,
        });
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
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.ordered()
            .into_iter()
            .find(|r| match &r.matcher {
                Matcher::DomainSuffix(s) => domain == *s || domain.ends_with(&format!(".{s}")),
                Matcher::Domain(d) => domain == *d,
                Matcher::DomainKeyword(k) => domain.contains(k.as_str()),
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

pub mod presets {
    use super::*;

    fn rule(layer: Layer, matcher: Matcher, action: Action) -> Rule {
        Rule {
            layer,
            matcher,
            action,
        }
    }

    pub const PRIVATE_NETWORKS: &[&str] = &[
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    ];

    /// Обновления Windows, Defender и OneDrive. Только узкие имена: остальной
    /// microsoft.com маршрутизируется как обычно.
    pub const WINDOWS_UPDATE_DOMAINS: &[&str] = &[
        "windowsupdate.com",
        "windowsupdate.microsoft.com",
        "update.microsoft.com",
        "delivery.mp.microsoft.com",
        "do.dsp.mp.microsoft.com",
        "wustat.windows.com",
        "ntservicepack.microsoft.com",
        "definitionupdates.microsoft.com",
        "onedrive.live.com",
        "storage.live.com",
        "api.onedrive.com",
        "d.docs.live.net",
        "oneclient.sfx.ms",
    ];

    /// Какие списки блокировок использовать.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ListMode {
        #[default]
        /// Отобранные списки itdoginfo (как в podkop): быстро и мало ложных срабатываний.
        Compact,
        /// Полный реестр блокировок runetfreedom (~700 тыс. доменов).
        Full,
    }

    fn set(name: &str) -> Matcher {
        Matcher::RuleSet(name.into())
    }

    /// «Россия — умный»: российское напрямую, заблокированное и сервисы с
    /// гео-блоком для РФ — через VPN. `everything_else` задаёт подрежим:
    /// Proxy = «всё, кроме РФ», Direct = «только заблокированное».
    pub fn russia_smart(everything_else: Action, mode: ListMode) -> RoutingPlan {
        let mut plan = RoutingPlan::new(everything_else);
        plan.extend(
            PRIVATE_NETWORKS
                .iter()
                .map(|c| rule(Layer::System, Matcher::IpCidr((*c).into()), Action::Direct)),
        );
        let p = Layer::Preset;
        // Обновления Windows, Defender и OneDrive: не тратят трафик подписки и не
        // тормозят из-за VPN. Свой сайт («Свои сайты») это правило перекрывает.
        plan.extend(
            WINDOWS_UPDATE_DOMAINS
                .iter()
                .map(|d| rule(p, Matcher::DomainSuffix((*d).into()), Action::Direct)),
        );
        match mode {
            ListMode::Compact => plan.extend([
                // Российские сайты, которые не открываются с зарубежных IP.
                rule(p, set("itdog:russia_outside"), Action::Direct),
                rule(p, set("itdog:russia_inside"), Action::Proxy),
            ]),
            ListMode::Full => plan.extend([
                rule(p, set("rf:ru-available-only-inside"), Action::Direct),
                rule(p, set("rf:ru-blocked"), Action::Proxy),
            ]),
        }
        plan.extend([
            // Сервисы, которые сами не пускают пользователей из РФ (ИИ, стриминг и т. п.).
            rule(p, set("itdog:geoblock"), Action::Proxy),
            rule(p, Matcher::DomainSuffix("ru".into()), Action::Direct),
            // .рф в punycode
            rule(p, Matcher::DomainSuffix("xn--p1ai".into()), Action::Direct),
            rule(p, Matcher::DomainSuffix("su".into()), Action::Direct),
            rule(p, set("rf:geoip-ru"), Action::Direct),
        ]);
        plan
    }

    /// Пользовательский выбор для сервиса или категории itdoginfo
    /// («YouTube через VPN», «TikTok напрямую»). Неизвестный id — `None`.
    pub fn list_choice(id: &str, action: Action) -> Option<Rule> {
        crate::lists::ITDOG_LISTS
            .iter()
            .any(|l| l.id == id)
            .then(|| rule(Layer::User, set(&format!("itdog:{id}")), action))
    }

    /// Настройки маршрутизации, которые выбирает пользователь (раздел
    /// «Маршрутизация»). Хранятся у приложения, план из них строит `from_settings`.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct RoutingSettings {
        pub list_mode: ListMode,
        /// Куда идёт всё, что не попало в списки: Proxy — «всё, кроме РФ, через VPN»,
        /// Direct — «через VPN только заблокированное».
        pub everything_else: Action,
        /// Выбор для отдельных списков itdoginfo: id → действие.
        pub overrides: std::collections::BTreeMap<String, Action>,
        /// Свои сайты и адреса. Важнее списков. Неверная запись пропускается, а не
        /// сбрасывает весь выбор.
        #[serde(deserialize_with = "lenient_custom")]
        pub custom: Vec<CustomRule>,
    }

    /// Свой сайт или адрес: домен со всеми поддоменами, IP или подсеть.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct CustomRule {
        pub target: String,
        pub action: Action,
    }

    fn lenient_custom<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<CustomRule>, D::Error> {
        let raw = Vec::<serde_json::Value>::deserialize(d)?;
        Ok(raw
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect())
    }

    /// Больше своих правил не берём: это ручной список, а не реестр.
    pub const MAX_CUSTOM_RULES: usize = 300;

    /// Разбор того, что ввёл пользователь: `https://www.Пример.рф/путь` →
    /// `xn--e1afmkfd.xn--p1ai`, `1.2.3.4` → `1.2.3.4/32`, `10.1.2.3/8` → `10.0.0.0/8`.
    /// Ошибка — готовый текст для интерфейса.
    pub fn custom_matcher(input: &str) -> Result<Matcher, &'static str> {
        parse_custom(input).map(|(m, _)| m)
    }

    /// Свой адрес для показа: кириллический домен остаётся кириллицей
    /// (`Пример.РФ` → `пример.рф`), остальное — как в правиле.
    pub fn custom_display(input: &str) -> Result<String, &'static str> {
        let (m, unicode) = parse_custom(input)?;
        Ok(match (m, unicode) {
            (_, Some(u)) => u,
            (Matcher::DomainSuffix(d), None) => d,
            // Один адрес — без `/32`: так его и вводят.
            (Matcher::IpCidr(c), None) => match c.split_once('/') {
                Some((ip, "32" | "128")) => ip.to_owned(),
                _ => c,
            },
            _ => {
                return Err(crate::i18n::tr(
                    "Не похоже на адрес сайта. Пример: example.com",
                    "Doesn't look like a site address. Example: example.com",
                ))
            }
        })
    }

    /// Правило и, для кириллического домена, его вид в Unicode.
    fn parse_custom(input: &str) -> Result<(Matcher, Option<String>), &'static str> {
        let not_a_site = crate::i18n::tr(
            crate::i18n::tr(
                "Не похоже на адрес сайта. Пример: example.com",
                "Doesn't look like a site address. Example: example.com",
            ),
            "Doesn't look like a site address. Example: example.com",
        );
        let text = input.trim();
        if text.is_empty() {
            return Err(crate::i18n::tr(
                "Введите адрес сайта, IP или подсеть.",
                "Enter a site address, IP or subnet.",
            ));
        }
        if text.len() > 300 || text.chars().any(char::is_whitespace) {
            return Err(crate::i18n::tr(
                "Одно правило — один адрес, без пробелов.",
                "One rule, one address, no spaces.",
            ));
        }
        if let Some(m) = cidr(text)? {
            return Ok((m, None));
        }
        // Ссылка целиком: схема, логин, путь и порт отбрасываются.
        let rest = text.split_once("://").map_or(text, |(_, r)| r);
        let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let rest = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
        if let Some(inner) = rest.strip_prefix('[') {
            // [2001:db8::1]:443
            let (ip, _) = inner.split_once(']').ok_or(not_a_site)?;
            return cidr(ip)?.ok_or(not_a_site).map(|m| (m, None));
        }
        let host = match rest.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => rest,
        };
        if let Some(m) = cidr(host)? {
            return Ok((m, None));
        }
        let host = host.to_lowercase();
        let host = host.trim_start_matches("*.").trim_matches('.');
        let host = host.strip_prefix("www.").unwrap_or(host);
        let domain = match url::Host::parse(host) {
            Ok(url::Host::Domain(d)) => d,
            Ok(url::Host::Ipv4(ip)) => return Ok((ip_cidr(ip.into(), None), None)),
            Ok(url::Host::Ipv6(ip)) => return Ok((ip_cidr(ip.into(), None), None)),
            Err(_) => return Err(not_a_site),
        };
        let labels_ok = domain
            .split('.')
            .all(|l| !l.starts_with('-') && !l.ends_with('-'));
        if !crate::zapret::valid_domain(&domain) || !labels_ok {
            return Err(not_a_site);
        }
        let unicode = (!host.is_ascii()).then(|| host.to_owned());
        Ok((Matcher::DomainSuffix(domain), unicode))
    }

    /// IP или подсеть; `Ok(None)` — это не адрес. Слишком широкие подсети
    /// отвергаются: для всего трафика есть «Всё остальное».
    fn cidr(text: &str) -> Result<Option<Matcher>, &'static str> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
            return Ok(None);
        };
        let (max, min) = if ip.is_ipv4() { (32, 8) } else { (128, 16) };
        let prefix = match prefix.map(str::parse::<u8>) {
            None => None,
            Some(Ok(n)) if n > max => {
                return Err(crate::i18n::tr(
                    "Неверная длина подсети.",
                    "Invalid subnet length.",
                ))
            }
            Some(Ok(n)) if n < min => {
                return Err(crate::i18n::tr(
                    "Подсеть слишком широкая — для всего трафика есть «Всё остальное».",
                    "The subnet is too wide — use “Everything else” for all traffic.",
                ))
            }
            Some(Ok(n)) => Some(n),
            Some(Err(_)) => {
                return Err(crate::i18n::tr(
                    "Неверная длина подсети.",
                    "Invalid subnet length.",
                ))
            }
        };
        Ok(Some(ip_cidr(ip, prefix)))
    }

    /// Подсеть в каноническом виде: биты адреса за префиксом обнуляются.
    fn ip_cidr(ip: std::net::IpAddr, prefix: Option<u8>) -> Matcher {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let text = match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(prefix.unwrap_or(32));
                let mask = u32::MAX.checked_shl(32 - n).unwrap_or(0);
                format!("{}/{n}", Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let n = u32::from(prefix.unwrap_or(128));
                let mask = u128::MAX.checked_shl(128 - n).unwrap_or(0);
                format!("{}/{n}", Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        Matcher::IpCidr(text)
    }

    /// Свои правила для плана: неверные и повторы пропускаются, не больше
    /// `MAX_CUSTOM_RULES`. Zapret здесь не бывает — только VPN, напрямую, блок.
    /// Ядро берёт первое совпавшее правило, поэтому узкие идут раньше широких:
    /// `mail.example.com` раньше `example.com`, `/24` раньше `/16` — порядок, в
    /// котором их добавили, на результат не влияет.
    pub fn custom_rules(custom: &[CustomRule]) -> Vec<Rule> {
        let mut seen = std::collections::HashSet::new();
        let mut rules: Vec<Rule> = custom
            .iter()
            .filter(|c| matches!(c.action, Action::Proxy | Action::Direct | Action::Block))
            .filter_map(|c| custom_matcher(&c.target).ok().map(|m| (m, c.action)))
            .filter(|(m, _)| seen.insert(m.clone()))
            .take(MAX_CUSTOM_RULES)
            .map(|(m, action)| rule(Layer::User, m, action))
            .collect();
        rules.sort_by_key(|r| std::cmp::Reverse(specificity(&r.matcher)));
        rules
    }

    /// Насколько узкое правило: число меток домена или длина префикса подсети.
    fn specificity(m: &Matcher) -> usize {
        match m {
            Matcher::DomainSuffix(d) => d.split('.').count(),
            Matcher::IpCidr(c) => c
                .rsplit_once('/')
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(0),
            _ => 0,
        }
    }

    impl Default for RoutingSettings {
        fn default() -> Self {
            Self {
                list_mode: ListMode::Compact,
                everything_else: Action::Proxy,
                overrides: Default::default(),
                custom: Vec::new(),
            }
        }
    }

    /// План по настройкам пользователя. Недопустимые значения (zapret для списка,
    /// неизвестный id, «блокировать всё остальное») пропускаются, а не ломают подключение.
    pub fn from_settings(s: &RoutingSettings) -> RoutingPlan {
        let everything_else = match s.everything_else {
            Action::Direct => Action::Direct,
            _ => Action::Proxy,
        };
        let mut plan = russia_smart(everything_else, s.list_mode);
        // Свой сайт важнее выбора для списка: в слое User они идут первыми.
        plan.extend(custom_rules(&s.custom));
        for (id, action) in &s.overrides {
            if matches!(action, Action::Proxy | Action::Direct | Action::Block) {
                if let Some(r) = list_choice(id, *action) {
                    plan.push(r);
                }
            }
        }
        plan
    }

    /// Сервисы, которые можно отдать zapret в гибридном режиме.
    pub fn zapret_youtube_discord() -> Vec<Rule> {
        [
            "youtube.com",
            "youtu.be",
            "googlevideo.com",
            "ytimg.com",
            "ggpht.com",
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
        ]
        .into_iter()
        .map(|d| {
            rule(
                Layer::Zapret,
                Matcher::DomainSuffix(d.into()),
                Action::Zapret,
            )
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::presets::*;
    use super::*;

    fn russia_smart(final_action: Action) -> RoutingPlan {
        super::presets::russia_smart(final_action, ListMode::Compact)
    }

    #[test]
    fn update_hosts_go_through_vpn_but_not_the_rest_of_github() {
        let plan = russia_smart(Action::Direct).with_update_hosts();
        assert_eq!(plan.resolve_domain("github.com"), Action::Proxy);
        assert_eq!(
            plan.resolve_domain("raw.githubusercontent.com"),
            Action::Proxy
        );
        assert_eq!(plan.resolve_domain("gist.github.com"), Action::Direct);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn health_check_goes_through_vpn_even_when_everything_else_is_direct() {
        let mut plan = russia_smart(Action::Direct).with_health_check();
        plan.push(Rule {
            layer: Layer::User,
            matcher: Matcher::DomainSuffix("cloudflare.com".into()),
            action: Action::Direct,
        });
        assert!(plan.validate().is_ok());
        assert_eq!(plan.resolve_domain(HEALTH_HOST), Action::Proxy);
    }

    #[test]
    fn presets_use_only_known_rule_sets() {
        for mode in [ListMode::Compact, ListMode::Full] {
            let plan = super::presets::russia_smart(Action::Proxy, mode);
            assert!(plan.validate().is_ok(), "{mode:?}");
        }
    }

    #[test]
    fn list_choice_overrides_preset() {
        let mut plan = russia_smart(Action::Proxy);
        plan.push(list_choice("youtube", Action::Direct).unwrap());
        let first = plan
            .ordered()
            .into_iter()
            .find(|r| r.layer == Layer::User)
            .unwrap();
        assert_eq!(first.matcher, Matcher::RuleSet("itdog:youtube".into()));
        assert!(plan.validate().is_ok());
        assert!(list_choice("../../evil", Action::Proxy).is_none());
    }

    #[test]
    fn settings_build_valid_plan_and_skip_bad_values() {
        let mut s = RoutingSettings::default();
        s.overrides.insert("youtube".into(), Action::Direct);
        s.overrides.insert("tiktok".into(), Action::Block);
        s.overrides.insert("discord".into(), Action::Zapret);
        s.overrides.insert("../../evil".into(), Action::Proxy);
        s.everything_else = Action::Block;
        let plan = from_settings(&s);
        assert!(plan.validate().is_ok());
        assert_eq!(plan.final_action, Action::Proxy);
        let user: Vec<_> = plan
            .ordered()
            .into_iter()
            .filter(|r| r.layer == Layer::User)
            .collect();
        assert_eq!(user.len(), 2);
        assert!(user
            .iter()
            .any(|r| r.matcher == Matcher::RuleSet("itdog:youtube".into())
                && r.action == Action::Direct));
    }

    #[test]
    fn settings_json_is_tolerant() {
        let s: RoutingSettings = serde_json::from_str(r#"{"listMode":"full"}"#).unwrap();
        assert_eq!(s.list_mode, ListMode::Full);
        assert_eq!(s.everything_else, Action::Proxy);
    }

    fn custom(target: &str) -> Result<Matcher, &'static str> {
        custom_matcher(target)
    }

    #[test]
    fn custom_targets_are_normalized() {
        let d = |s: &str| Ok(Matcher::DomainSuffix(s.into()));
        let ip = |s: &str| Ok(Matcher::IpCidr(s.into()));
        assert_eq!(custom("Example.COM"), d("example.com"));
        assert_eq!(custom("https://www.example.com/a?b#c"), d("example.com"));
        assert_eq!(custom("*.example.com"), d("example.com"));
        assert_eq!(custom("user:pw@example.com:8443/x"), d("example.com"));
        assert_eq!(custom("пример.рф"), d("xn--e1afmkfd.xn--p1ai"));
        assert_eq!(
            custom_display("https://www.Пример.РФ/путь").unwrap(),
            "пример.рф"
        );
        assert_eq!(custom_display("WWW.Example.com").unwrap(), "example.com");
        assert_eq!(custom_display("10.1.2.3/8").unwrap(), "10.0.0.0/8");
        assert_eq!(custom_display("1.2.3.4/32").unwrap(), "1.2.3.4");
        assert_eq!(custom_display("[2001:db8::1]:443").unwrap(), "2001:db8::1");
        assert_eq!(custom(" sub.example.org. "), d("sub.example.org"));
        assert_eq!(custom("1.2.3.4"), ip("1.2.3.4/32"));
        assert_eq!(custom("http://1.2.3.4:8080/"), ip("1.2.3.4/32"));
        assert_eq!(custom("10.1.2.3/8"), ip("10.0.0.0/8"));
        assert_eq!(custom("2001:db8::1"), ip("2001:db8::1/128"));
        assert_eq!(custom("[2001:db8::1]:443"), ip("2001:db8::1/128"));
        assert_eq!(custom("2001:db8:1::/48"), ip("2001:db8:1::/48"));
    }

    #[test]
    fn bad_custom_targets_are_rejected() {
        for bad in [
            "",
            "   ",
            "two words.com",
            "0.0.0.0/0",
            "1.2.3.4/33",
            "1.2.3.4/x",
            "::/0",
            "exa_mple.com",
            "-bad.com",
            "регулярка.*",
            "regexp:.*",
            "domain:evil.com",
            "a..b",
            "[::1",
        ] {
            assert!(custom(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}.com", "a".repeat(400));
        assert!(custom(&long).is_err());
    }

    #[test]
    fn custom_rules_beat_lists_and_skip_bad_values() {
        let mut s = RoutingSettings::default();
        s.overrides.insert("youtube".into(), Action::Direct);
        s.custom = vec![
            CustomRule {
                target: "https://www.YouTube.com/watch".into(),
                action: Action::Proxy,
            },
            CustomRule {
                target: "youtube.com".into(),
                action: Action::Block,
            },
            CustomRule {
                target: "gosuslugi.ru".into(),
                action: Action::Proxy,
            },
            CustomRule {
                target: "discord.com".into(),
                action: Action::Zapret,
            },
            CustomRule {
                target: "not a site".into(),
                action: Action::Direct,
            },
        ];
        let plan = from_settings(&s);
        assert!(plan.validate().is_ok());
        // Повтор не перекрывает первое правило; zapret и мусор пропущены.
        assert_eq!(custom_rules(&s.custom).len(), 2);
        let user: Vec<_> = plan
            .ordered()
            .into_iter()
            .filter(|r| r.layer == Layer::User)
            .collect();
        assert_eq!(user[0].matcher, Matcher::DomainSuffix("youtube.com".into()));
        assert_eq!(user[0].action, Action::Proxy);
        assert_eq!(plan.resolve_domain("m.youtube.com"), Action::Proxy);
        // Свой сайт сильнее пресета «.ru напрямую».
        assert_eq!(plan.resolve_domain("www.gosuslugi.ru"), Action::Proxy);
    }

    #[test]
    fn narrow_custom_rule_wins_regardless_of_order() {
        let s = RoutingSettings {
            custom: vec![
                CustomRule {
                    target: "example.com".into(),
                    action: Action::Direct,
                },
                CustomRule {
                    target: "mail.example.com".into(),
                    action: Action::Proxy,
                },
                CustomRule {
                    target: "10.20.0.0/16".into(),
                    action: Action::Proxy,
                },
                CustomRule {
                    target: "10.20.30.0/24".into(),
                    action: Action::Block,
                },
            ],
            ..Default::default()
        };
        let plan = from_settings(&s);
        assert_eq!(plan.resolve_domain("mail.example.com"), Action::Proxy);
        assert_eq!(plan.resolve_domain("www.example.com"), Action::Direct);
        let ips: Vec<_> = plan
            .ordered()
            .into_iter()
            .filter_map(|r| match (&r.layer, &r.matcher) {
                (Layer::User, Matcher::IpCidr(c)) => Some(c.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(ips, ["10.20.30.0/24", "10.20.0.0/16"]);
    }

    #[test]
    fn custom_rules_are_capped() {
        let custom: Vec<_> = (0..MAX_CUSTOM_RULES + 50)
            .map(|i| CustomRule {
                target: format!("site{i}.example.com"),
                action: Action::Direct,
            })
            .collect();
        assert_eq!(custom_rules(&custom).len(), MAX_CUSTOM_RULES);
    }

    #[test]
    fn user_direct_drops_domain_from_zapret() {
        let mut plan = hybrid();
        plan.extend(custom_rules(&[CustomRule {
            target: "youtube.com".into(),
            action: Action::Direct,
        }]));
        assert_eq!(plan.resolve_domain("youtube.com"), Action::Direct);
        assert!(!plan.zapret_hostlist().contains(&"youtube.com".to_string()));
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn windows_update_goes_direct_but_not_all_of_microsoft() {
        let plan = russia_smart(Action::Proxy);
        for host in [
            "fe3.delivery.mp.microsoft.com",
            "download.windowsupdate.com",
            "sls.update.microsoft.com",
            "definitionupdates.microsoft.com",
        ] {
            assert_eq!(plan.resolve_domain(host), Action::Direct, "{host}");
        }
        assert_eq!(plan.resolve_domain("microsoft.com"), Action::Proxy);
        assert_eq!(plan.resolve_domain("login.live.com"), Action::Proxy);
        // Свой сайт перекрывает пресет.
        let mut s = RoutingSettings::default();
        s.custom.push(CustomRule {
            target: "windowsupdate.com".into(),
            action: Action::Proxy,
        });
        assert_eq!(
            from_settings(&s).resolve_domain("download.windowsupdate.com"),
            Action::Proxy
        );
    }

    #[test]
    fn old_settings_without_custom_load() {
        let s: RoutingSettings = serde_json::from_str(
            r#"{"listMode":"compact","everythingElse":"direct","overrides":{}}"#,
        )
        .unwrap();
        assert!(s.custom.is_empty());
        let s: RoutingSettings = serde_json::from_str(
            r#"{"custom":[{"target":"example.com","action":"direct"},{"target":"x","action":"weird"}]}"#,
        )
        .unwrap();
        assert_eq!(s.custom.len(), 1);
    }

    #[test]
    fn unknown_rule_set_is_rejected() {
        let mut plan = russia_smart(Action::Proxy);
        plan.push(Rule {
            layer: Layer::Provider,
            matcher: Matcher::RuleSet("rf:../../windows".into()),
            action: Action::Proxy,
        });
        assert!(matches!(
            plan.validate(),
            Err(RoutingError::UnknownRuleSet(_))
        ));
    }

    /// Злой клиент службы: префиксы ядра, пути, имя процесса с путём — отказ;
    /// обычные домены, подсети и имена программ — проходят.
    #[test]
    fn bad_matcher_strings_are_rejected() {
        let bad = [
            Matcher::IpCidr(r"ext:..\..\x.dat:tag".into()),
            Matcher::IpCidr("10.0.0.0/33".into()),
            Matcher::Domain("regexp:.*".into()),
            Matcher::DomainSuffix("a..b".into()),
            Matcher::DomainSuffix(".example.com".into()),
            Matcher::DomainKeyword("geosite:ru".into()),
            Matcher::ProcessName(r"C:\Windows\x.exe".into()),
            Matcher::ProcessName(String::new()),
        ];
        for matcher in bad {
            let mut plan = russia_smart(Action::Proxy);
            plan.push(Rule {
                layer: Layer::User,
                matcher: matcher.clone(),
                action: Action::Direct,
            });
            assert!(
                matches!(plan.validate(), Err(RoutingError::InvalidMatcher(_))),
                "{matcher:?}"
            );
        }
        let good = [
            Matcher::IpCidr("1.2.3.4".into()),
            Matcher::IpCidr("fe80::/10".into()),
            Matcher::DomainSuffix("xn--e1afmkfd.xn--p1ai".into()),
            Matcher::Domain("_srv.example.com".into()),
            Matcher::DomainKeyword("google".into()),
            Matcher::ProcessName("Telegram.exe".into()),
        ];
        let mut plan = russia_smart(Action::Proxy);
        for matcher in good {
            plan.push(Rule {
                layer: Layer::User,
                matcher,
                action: Action::Direct,
            });
        }
        assert!(plan.validate().is_ok());
    }

    fn hybrid() -> RoutingPlan {
        let mut plan = russia_smart(Action::Proxy)
            .with_servers(["203.0.113.10".to_string(), "vpn.example.com".into()]);
        plan.extend(zapret_youtube_discord());
        plan
    }

    #[test]
    fn russian_domains_go_direct() {
        let plan = russia_smart(Action::Proxy);
        assert_eq!(plan.resolve_domain("gosuslugi.ru"), Action::Direct);
        assert_eq!(
            plan.resolve_domain("xn--80ajghhoc2aj1c8b.xn--p1ai"),
            Action::Direct
        );
        assert_eq!(plan.resolve_domain("example.com"), Action::Proxy);
        assert_eq!(
            russia_smart(Action::Direct).resolve_domain("example.com"),
            Action::Direct
        );
    }

    #[test]
    fn suffix_does_not_match_partial_labels() {
        let plan = russia_smart(Action::Proxy);
        assert_eq!(plan.resolve_domain("notru"), Action::Proxy);
    }

    #[test]
    fn hybrid_sends_youtube_to_zapret() {
        let plan = hybrid();
        assert!(plan.validate().is_ok());
        assert_eq!(
            plan.resolve_domain("rr3---sn-abc.googlevideo.com"),
            Action::Zapret
        );
        assert!(plan.zapret_hostlist().contains(&"youtube.com".to_string()));
        assert_eq!(
            plan.zapret_exclusions(),
            ["203.0.113.10", "vpn.example.com"]
        );
    }

    #[test]
    fn server_domain_is_never_zapret() {
        let mut plan =
            RoutingPlan::new(Action::Proxy).with_servers(["edge.discord.com".to_string()]);
        plan.extend(zapret_youtube_discord());
        // Системный слой выше zapret, поэтому адрес сервера остаётся Direct.
        assert_eq!(plan.resolve_domain("edge.discord.com"), Action::Direct);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn user_rule_overrides_zapret_and_drops_it_from_hostlist() {
        let mut plan = hybrid();
        plan.push(Rule {
            layer: Layer::User,
            matcher: Matcher::DomainSuffix("discord.com".into()),
            action: Action::Proxy,
        });
        assert_eq!(plan.resolve_domain("discord.com"), Action::Proxy);
        assert!(!plan.zapret_hostlist().contains(&"discord.com".to_string()));
    }

    #[test]
    fn provider_cannot_use_zapret() {
        let mut plan = RoutingPlan::new(Action::Proxy);
        plan.push(Rule {
            layer: Layer::Provider,
            matcher: Matcher::DomainSuffix("x.com".into()),
            action: Action::Zapret,
        });
        assert_eq!(plan.validate(), Err(RoutingError::ProviderZapret));
    }
}
