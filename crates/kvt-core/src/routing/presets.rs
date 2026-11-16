//! Готовые наборы правил и настройки маршрутизации: из `RoutingSettings` пользователя
//! строится `RoutingPlan`. Свои сайты и адреса («Свои сайты» в окне) разбираются здесь же.

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
