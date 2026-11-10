//! Каталог списков маршрутизации.
//!
//! - **itdoginfo/allow-domains** (их использует podkop) — компактные отобранные
//!   списки и сервисы. Лицензия не указана, поэтому списки не поставляются с
//!   программой, а скачиваются при запуске.
//! - **runetfreedom/russia-v2ray-rules-dat** (GPL-3.0) — полный список блокировок
//!   и `geoip:ru`.
//!
//! В `Matcher::RuleSet` набор записывается как `itdog:<id>` или `rf:<имя>`
//! (`rf:geoip-<код>` — IP-набор).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListKind {
    Region,
    Category,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ListInfo {
    /// Имя как в релизах itdoginfo: `<id>.srs`.
    pub id: &'static str,
    pub title: &'static str,
    pub kind: ListKind,
    /// Что входит в список — подсказка под названием. Пусто, если нечего добавить.
    pub hint: &'static str,
}

const fn list(
    id: &'static str,
    title: &'static str,
    kind: ListKind,
    hint: &'static str,
) -> ListInfo {
    ListInfo {
        id,
        title,
        kind,
        hint,
    }
}

use ListKind::{Category, Region, Service};

/// Все списки itdoginfo (как в community lists podkop).
pub const ITDOG_LISTS: &[ListInfo] = &[
    list(
        "russia_inside",
        "Заблокировано в России",
        Region,
        "Сайты и сервисы из реестра блокировок и замедленные",
    ),
    list(
        "russia_outside",
        "Российские сайты, закрытые для зарубежа",
        Region,
        "Госуслуги, банки, магазины — не открываются с зарубежных IP",
    ),
    list(
        "ukraine_inside",
        "Заблокировано в Украине",
        Region,
        "Российские сервисы, закрытые в Украине",
    ),
    list(
        "geoblock",
        "Сервисы, закрытые для России",
        Category,
        "ИИ, стриминг и магазины, которые сами не пускают из России",
    ),
    list("block", "Заблокированные сайты", Category, ""),
    list("news", "Новости", Category, "Заблокированные СМИ"),
    list("anime", "Аниме", Category, "Сайты с аниме"),
    list("porn", "18+", Category, "Сайты для взрослых"),
    list(
        "hodca",
        "Хостинги",
        Category,
        "Hetzner, OVH, DigitalOcean, Cloudflare, AWS — адреса целиком",
    ),
    list(
        "youtube",
        "YouTube",
        Service,
        "youtube.com, googlevideo.com, ytimg.com",
    ),
    list(
        "discord",
        "Discord",
        Service,
        "discord.com, discord.gg, голосовые серверы",
    ),
    list(
        "telegram",
        "Telegram",
        Service,
        "t.me, telegram.org и адреса серверов",
    ),
    list(
        "meta",
        "Meta",
        Service,
        "Instagram, Facebook, WhatsApp, Threads",
    ),
    list(
        "twitter",
        "X (Twitter)",
        Service,
        "x.com, twitter.com, twimg.com",
    ),
    list(
        "tiktok",
        "TikTok",
        Service,
        "tiktok.com и сеть доставки видео",
    ),
    list("hdrezka", "HDRezka", Service, "Сайт и зеркала"),
    list(
        "google_ai",
        "Google AI",
        Service,
        "Gemini, AI Studio, NotebookLM",
    ),
    list(
        "google_play",
        "Google Play",
        Service,
        "Магазин приложений и загрузки",
    ),
    list("google_meet", "Google Meet", Service, "Видеозвонки Google"),
    list("roblox", "Roblox", Service, ""),
    list(
        "cloudflare",
        "Cloudflare",
        Service,
        "Адреса сети Cloudflare",
    ),
    list(
        "cloudfront",
        "Amazon CloudFront",
        Service,
        "Адреса сети CloudFront",
    ),
    list("digitalocean", "DigitalOcean", Service, "Адреса хостинга"),
    list("hetzner", "Hetzner", Service, "Адреса хостинга"),
    list("ovh", "OVH", Service, "Адреса хостинга"),
];

/// Ссылка на набор правил в `Matcher::RuleSet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSetRef<'a> {
    Itdog(&'a str),
    /// Доменный набор runetfreedom (`geosite:<имя>`).
    RfSite(&'a str),
    /// IP-набор runetfreedom (`geoip:<код>`).
    RfIp(&'a str),
}

impl<'a> RuleSetRef<'a> {
    pub fn parse(name: &'a str) -> Option<Self> {
        if let Some(id) = name.strip_prefix("itdog:") {
            return ITDOG_LISTS
                .iter()
                .any(|l| l.id == id)
                .then_some(Self::Itdog(id));
        }
        let rest = name.strip_prefix("rf:")?;
        let valid = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_!@".contains(c))
        };
        match rest.strip_prefix("geoip-") {
            Some(code) if valid(code) => Some(Self::RfIp(code)),
            None if valid(rest) => Some(Self::RfSite(rest)),
            _ => None,
        }
    }

    pub fn is_ip_only(&self) -> bool {
        matches!(self, Self::RfIp(_))
    }

    /// Файл набора для sing-box в каталоге правил.
    pub fn srs_file(&self) -> String {
        match self {
            Self::Itdog(id) => format!("itdog-{id}.srs"),
            Self::RfSite(name) => format!("rf-geosite-{name}.srs"),
            Self::RfIp(code) => format!("rf-geoip-{code}.srs"),
        }
    }

    /// Выражение для правила Xray (`domain` или `ip`).
    pub fn xray_expr(&self) -> String {
        match self {
            Self::Itdog(id) => format!("ext:{ITDOG_XRAY_DAT}:{}", id.replace('_', "-")),
            Self::RfSite(name) => format!("geosite:{name}"),
            Self::RfIp(code) => format!("geoip:{code}"),
        }
    }

    /// Файл, который нужен Xray для этого набора.
    pub fn xray_file(&self) -> &'static str {
        match self {
            Self::Itdog(_) => ITDOG_XRAY_DAT,
            Self::RfSite(_) => "geosite.dat",
            Self::RfIp(_) => "geoip.dat",
        }
    }
}

/// geosite.dat itdoginfo кладётся под своим именем, чтобы не конфликтовать с runetfreedom.
pub const ITDOG_XRAY_DAT: &str = "itdog-geosite.dat";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_map() {
        let r = RuleSetRef::parse("itdog:google_ai").unwrap();
        assert_eq!(r.srs_file(), "itdog-google_ai.srs");
        assert_eq!(r.xray_expr(), "ext:itdog-geosite.dat:google-ai");

        let r = RuleSetRef::parse("rf:geoip-ru").unwrap();
        assert!(r.is_ip_only());
        assert_eq!(r.srs_file(), "rf-geoip-ru.srs");
        assert_eq!(r.xray_expr(), "geoip:ru");

        let r = RuleSetRef::parse("rf:category-ai-!cn").unwrap();
        assert_eq!(r.xray_expr(), "geosite:category-ai-!cn");
    }

    #[test]
    fn unknown_or_unsafe_names_rejected() {
        assert_eq!(RuleSetRef::parse("itdog:nonexistent"), None);
        assert_eq!(RuleSetRef::parse("rf:../../etc"), None);
        assert_eq!(RuleSetRef::parse("rf:geoip-"), None);
        assert_eq!(RuleSetRef::parse("ru-blocked"), None);
    }
}
