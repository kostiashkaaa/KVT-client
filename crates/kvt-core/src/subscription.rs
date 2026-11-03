//! Метаданные подписки из HTTP-заголовков (общепринятые для панелей
//! Marzban/Remnawave/3x-ui) и расписание обновлений без «спама» запросами.

use crate::parser::decode_base64_lenient;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Чаще раза в час подписку не обновляем, даже если провайдер просит.
pub const MIN_UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
pub const MAX_UPDATE_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Лимит размера ответа подписки.
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_ANNOUNCE_CHARS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionMeta {
    pub title: Option<String>,
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    /// Unix-время окончания подписки.
    pub expire: Option<u64>,
    pub update_interval: Duration,
    /// Только https-ссылки; остальные отбрасываются.
    pub support_url: Option<String>,
    pub web_page_url: Option<String>,
    /// Текст провайдера. В UI выводится только как текст, без HTML.
    pub announce: Option<String>,
}

impl Default for SubscriptionMeta {
    fn default() -> Self {
        Self {
            title: None,
            upload: None,
            download: None,
            total: None,
            expire: None,
            update_interval: DEFAULT_UPDATE_INTERVAL,
            support_url: None,
            web_page_url: None,
            announce: None,
        }
    }
}

impl SubscriptionMeta {
    pub fn used_bytes(&self) -> Option<u64> {
        match (self.upload, self.download) {
            (None, None) => None,
            (u, d) => Some(u.unwrap_or(0).saturating_add(d.unwrap_or(0))),
        }
    }
}

/// Разбирает заголовки ответа подписки (имена без учёта регистра).
pub fn parse_headers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> SubscriptionMeta {
    let mut meta = SubscriptionMeta::default();
    for (name, value) in headers {
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "profile-title" => meta.title = decode_maybe_base64(value).map(|t| clean_text(&t, 100)),
            "subscription-userinfo" => parse_userinfo(value, &mut meta),
            "profile-update-interval" => {
                if let Ok(hours) = value.parse::<u64>() {
                    meta.update_interval = Duration::from_secs(hours.saturating_mul(3600))
                        .clamp(MIN_UPDATE_INTERVAL, MAX_UPDATE_INTERVAL);
                }
            }
            "support-url" => meta.support_url = https_only(value),
            "profile-web-page-url" => meta.web_page_url = https_only(value),
            "announce" => {
                meta.announce =
                    decode_maybe_base64(value).map(|t| clean_text(&t, MAX_ANNOUNCE_CHARS))
            }
            _ => {}
        }
    }
    meta
}

/// `upload=123; download=456; total=789; expire=1767225600`
fn parse_userinfo(value: &str, meta: &mut SubscriptionMeta) {
    for part in value.split(';') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let v = v.trim().parse::<u64>().ok();
        match k.trim().to_ascii_lowercase().as_str() {
            "upload" => meta.upload = v,
            "download" => meta.download = v,
            "total" => meta.total = v.filter(|t| *t > 0),
            "expire" => meta.expire = v.filter(|t| *t > 0),
            _ => {}
        }
    }
}

fn decode_maybe_base64(value: &str) -> Option<String> {
    let text = match value.strip_prefix("base64:") {
        Some(b64) => String::from_utf8(decode_base64_lenient(b64)?).ok()?,
        None => value.to_owned(),
    };
    Some(text).filter(|t| !t.trim().is_empty())
}

/// Убирает управляющие символы и обрезает длину — данные провайдера недоверенные.
fn clean_text(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn https_only(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    (url.scheme() == "https" && url.host_str().is_some()).then(|| url.to_string())
}

/// Задержка до следующего обновления с разбросом ±15 %, чтобы клиенты не
/// ходили за подпиской синхронно. `unit` — случайное число из [0, 1).
pub fn next_update_delay(interval: Duration, unit: f64) -> Duration {
    let unit = unit.clamp(0.0, 1.0);
    let factor = 0.85 + 0.30 * unit;
    interval.mul_f64(factor).max(MIN_UPDATE_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_headers() {
        let meta = parse_headers([
            ("Profile-Title", "base64:0JzQvtC5IFZQTg=="),
            (
                "subscription-userinfo",
                "upload=100; download=900; total=10000; expire=1767225600",
            ),
            ("profile-update-interval", "6"),
            ("support-url", "https://t.me/support"),
            ("profile-web-page-url", "http://insecure.example.com"),
        ]);
        assert_eq!(meta.title.as_deref(), Some("Мой VPN"));
        assert_eq!(meta.used_bytes(), Some(1000));
        assert_eq!(meta.total, Some(10000));
        assert_eq!(meta.expire, Some(1_767_225_600));
        assert_eq!(meta.update_interval, Duration::from_secs(6 * 3600));
        assert_eq!(meta.support_url.as_deref(), Some("https://t.me/support"));
        assert_eq!(meta.web_page_url, None);
    }

    #[test]
    fn update_interval_is_clamped() {
        let meta = parse_headers([("profile-update-interval", "0")]);
        assert_eq!(meta.update_interval, MIN_UPDATE_INTERVAL);
    }

    #[test]
    fn announce_is_sanitized() {
        let long = format!("a\u{0007}b{}", "x".repeat(1000));
        let meta = parse_headers([("announce", long.as_str())]);
        let text = meta.announce.unwrap();
        assert!(text.starts_with("ab"));
        assert_eq!(text.chars().count(), MAX_ANNOUNCE_CHARS);
    }

    #[test]
    fn jitter_stays_in_bounds() {
        let base = Duration::from_secs(10 * 3600);
        let close = |a: Duration, b_secs: u64| a.as_secs().abs_diff(b_secs) <= 1;
        assert!(close(next_update_delay(base, 0.0), 30_600)); // 8,5 ч
        assert!(close(next_update_delay(base, 1.0), 41_400)); // 11,5 ч
        assert_eq!(next_update_delay(Duration::ZERO, 0.5), MIN_UPDATE_INTERVAL);
    }
}
