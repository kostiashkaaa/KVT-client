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

use crate::i18n::Text;
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
    pub title: Text,
    pub kind: ListKind,
    /// Что входит в список — подсказка под названием. Пусто, если нечего добавить.
    pub hint: Text,
}

const fn list(id: &'static str, title: Text, kind: ListKind, hint: Text) -> ListInfo {
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
        Text::new("Заблокировано в России", "Blocked in Russia"),
        Region,
        Text::new(
            "Сайты и сервисы из реестра блокировок и замедленные",
            "Sites and services from the block registry, plus throttled ones",
        ),
    ),
    list(
        "russia_outside",
        Text::new(
            "Российские сайты, закрытые для зарубежа",
            "Russian sites closed to foreign visitors",
        ),
        Region,
        Text::new(
            "Госуслуги, банки, магазины — не открываются с зарубежных IP",
            "Gosuslugi, banks, shops — don't open from foreign IPs",
        ),
    ),
    list(
        "ukraine_inside",
        Text::new("Заблокировано в Украине", "Blocked in Ukraine"),
        Region,
        Text::new(
            "Российские сервисы, закрытые в Украине",
            "Russian services blocked in Ukraine",
        ),
    ),
    list(
        "geoblock",
        Text::new("Сервисы, закрытые для России", "Services closed to Russia"),
        Category,
        Text::new(
            "ИИ, стриминг и магазины, которые сами не пускают из России",
            "AI, streaming and shops that refuse visitors from Russia",
        ),
    ),
    list(
        "block",
        Text::new("Заблокированные сайты", "Blocked sites"),
        Category,
        Text::same(""),
    ),
    list(
        "news",
        Text::new("Новости", "News"),
        Category,
        Text::new("Заблокированные СМИ", "Blocked media"),
    ),
    list(
        "anime",
        Text::new("Аниме", "Anime"),
        Category,
        Text::new("Сайты с аниме", "Anime sites"),
    ),
    list(
        "porn",
        Text::same("18+"),
        Category,
        Text::new("Сайты для взрослых", "Adult sites"),
    ),
    list(
        "hodca",
        Text::new("Хостинги", "Hosting"),
        Category,
        Text::new(
            "Hetzner, OVH, DigitalOcean, Cloudflare, AWS — адреса целиком",
            "Hetzner, OVH, DigitalOcean, Cloudflare, AWS — whole address ranges",
        ),
    ),
    list(
        "youtube",
        Text::same("YouTube"),
        Service,
        Text::same("youtube.com, googlevideo.com, ytimg.com"),
    ),
    list(
        "discord",
        Text::same("Discord"),
        Service,
        Text::new(
            "discord.com, discord.gg, голосовые серверы",
            "discord.com, discord.gg, voice servers",
        ),
    ),
    list(
        "telegram",
        Text::same("Telegram"),
        Service,
        Text::new(
            "t.me, telegram.org и адреса серверов",
            "t.me, telegram.org and server addresses",
        ),
    ),
    list(
        "meta",
        Text::same("Meta"),
        Service,
        Text::same("Instagram, Facebook, WhatsApp, Threads"),
    ),
    list(
        "twitter",
        Text::same("X (Twitter)"),
        Service,
        Text::same("x.com, twitter.com, twimg.com"),
    ),
    list(
        "tiktok",
        Text::same("TikTok"),
        Service,
        Text::new(
            "tiktok.com и сеть доставки видео",
            "tiktok.com and its video CDN",
        ),
    ),
    list(
        "hdrezka",
        Text::same("HDRezka"),
        Service,
        Text::new("Сайт и зеркала", "Site and mirrors"),
    ),
    list(
        "google_ai",
        Text::same("Google AI"),
        Service,
        Text::same("Gemini, AI Studio, NotebookLM"),
    ),
    list(
        "google_play",
        Text::same("Google Play"),
        Service,
        Text::new("Магазин приложений и загрузки", "App store and downloads"),
    ),
    list(
        "google_meet",
        Text::same("Google Meet"),
        Service,
        Text::new("Видеозвонки Google", "Google video calls"),
    ),
    list("roblox", Text::same("Roblox"), Service, Text::same("")),
    list(
        "cloudflare",
        Text::same("Cloudflare"),
        Service,
        Text::new("Адреса сети Cloudflare", "Cloudflare network addresses"),
    ),
    list(
        "cloudfront",
        Text::same("Amazon CloudFront"),
        Service,
        Text::new("Адреса сети CloudFront", "CloudFront network addresses"),
    ),
    list(
        "digitalocean",
        Text::same("DigitalOcean"),
        Service,
        Text::new("Адреса хостинга", "Hosting addresses"),
    ),
    list(
        "hetzner",
        Text::same("Hetzner"),
        Service,
        Text::new("Адреса хостинга", "Hosting addresses"),
    ),
    list(
        "ovh",
        Text::same("OVH"),
        Service,
        Text::new("Адреса хостинга", "Hosting addresses"),
    ),
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
