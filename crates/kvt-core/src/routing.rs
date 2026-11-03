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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Matcher {
    /// Домен и все его поддомены.
    DomainSuffix(String),
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("адрес VPN-сервера «{0}» попал под zapret")]
    ServerUnderZapret(String),
    #[error("правила подписки не могут включать zapret")]
    ProviderZapret,
    #[error("правило zapret должно задаваться доменом")]
    ZapretNeedsDomain,
    /// Имя набора превращается в путь к файлу, поэтому неизвестные имена отвергаются.
    #[error("неизвестный набор правил «{0}»")]
    UnknownRuleSet(String),
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
    }

    impl Default for RoutingSettings {
        fn default() -> Self {
            Self {
                list_mode: ListMode::Compact,
                everything_else: Action::Proxy,
                overrides: Default::default(),
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
