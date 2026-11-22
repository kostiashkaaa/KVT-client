//! «Проверить VPN»: с какого адреса и из какой страны видят снаружи, и какая
//! скорость — через VPN и напрямую. Здесь типы и разбор ответов без сети;
//! запросы шлёт окно (`vpncheck` в kvt-app): через туннель — системным правилом
//! (`routing::TRACE_URLS` и `SPEED_URLS`, все имена — `PROBE_HOSTS`), «напрямую»
//! — с адреса физического адаптера. Cloudflare может быть недоступен из России —
//! поэтому источников несколько, по порядку, пока один не ответит. Пути и их
//! ограничения (kill switch, работающий zapret) — `sitecheck`.

use crate::sitecheck::{Path, Running, SkippedPath};
use serde::{Deserialize, Serialize};

/// Меньше — скорость не показательная: отклик CDN не везде быстрый, а полсекунды
/// замера — это погрешность, а не скорость.
const MIN_SPEED_BYTES: u64 = 64 * 1024;
const MIN_SPEED_MS: u64 = 500;

/// Что показывают по одному пути.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SideView {
    /// Адрес, с которого видят сайты.
    pub ip: Option<String>,
    /// Страна выхода, код ISO.
    pub country: Option<String>,
    /// Скорость скачивания, КБ/с. `None` — не измерилась или не показательная.
    pub kbps: Option<u64>,
    /// Сколько шёл запрос адреса.
    pub ms: Option<u64>,
    /// Какой источник ответил адресом (`cloudflare`, `sypexgeo`, `ipwho.is`) —
    /// показывается, когда основной недоступен.
    pub trace_via: Option<String>,
    /// Каким источником измерена скорость (`cloudflare`, `ovh`).
    pub speed_via: Option<String>,
}

/// Итог одного пути.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Side {
    /// Ответ есть; чего не вышло — внутри `None`.
    Ok(Box<SideView>),
    /// Запрос не прошёл: пути нет или он закрыт.
    Failed,
    /// `NetGovernor` отложил соединение (заморозка после прошлых проб).
    Deferred,
}

/// Итог одного пути с его меткой.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathSide {
    pub path: Path,
    pub side: Side,
}

/// Итог проверки для окна.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub running: Running,
    pub sides: Vec<PathSide>,
    pub skipped: Vec<SkippedPath>,
}

/// Разбор ответа «адрес и страна». Формат зависит от источника (`routing::TRACE_URLS`),
/// ответ приходит из сети — каждую строку и поле проверяем, мусор отбрасываем.
pub fn parse_trace(source: &str, body: &str) -> (Option<String>, Option<String>) {
    match source {
        "cloudflare" => parse_cloudflare(body),
        "sypexgeo" => parse_sypexgeo(body),
        "ipwho.is" => parse_ipwho(body),
        _ => (None, None),
    }
}

/// Строки `ip=` и `loc=` из ответа `/cdn-cgi/trace`.
fn parse_cloudflare(body: &str) -> (Option<String>, Option<String>) {
    let mut ip = None;
    let mut country = None;
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("ip=") {
            let v = v.trim();
            if v.parse::<std::net::IpAddr>().is_ok() {
                ip = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("loc=") {
            let v = v.trim();
            if v.len() == 2 && v.chars().all(|c| c.is_ascii_alphabetic()) {
                country = Some(v.to_ascii_uppercase());
            }
        }
    }
    (ip, country)
}

/// Адрес и страна из двух букв — `AA` и ровно две буквы в верхнем регистре.
fn clean(ip: Option<String>, country: Option<String>) -> (Option<String>, Option<String>) {
    let ip = ip.filter(|v| v.parse::<std::net::IpAddr>().is_ok());
    let country = country
        .filter(|v| v.len() == 2 && v.chars().all(|c| c.is_ascii_alphabetic()))
        .map(|v| v.to_ascii_uppercase());
    (ip, country)
}

/// JSON sypexgeo: `{"ip":"…","country":{"iso":"RU"},…}` — российский сервис,
/// запасной, когда Cloudflare недоступен напрямую.
fn parse_sypexgeo(body: &str) -> (Option<String>, Option<String>) {
    #[derive(Deserialize)]
    struct Sypex {
        ip: Option<String>,
        country: Option<SypexCountry>,
    }
    #[derive(Deserialize)]
    struct SypexCountry {
        iso: Option<String>,
    }
    match serde_json::from_str::<Sypex>(body) {
        Ok(v) => clean(v.ip, v.country.and_then(|c| c.iso)),
        Err(_) => (None, None),
    }
}

/// JSON ipwho.is: `{"success":true,"ip":"…","country_code":"DK",…}` — HTTPS,
/// второй запасной.
fn parse_ipwho(body: &str) -> (Option<String>, Option<String>) {
    #[derive(Deserialize)]
    struct Ipwho {
        success: Option<bool>,
        ip: Option<String>,
        country_code: Option<String>,
    }
    match serde_json::from_str::<Ipwho>(body) {
        Ok(v) if v.success == Some(true) => clean(v.ip, v.country_code),
        _ => (None, None),
    }
}

/// Скорость из замера, КБ/с: сколько байт за сколько миллисекунд. Замер короче
/// полсекунды или меньше 64 КБ не показывает скорость — молчим.
pub fn kbps(bytes: u64, ms: u64) -> Option<u64> {
    if bytes < MIN_SPEED_BYTES || ms < MIN_SPEED_MS {
        return None;
    }
    Some(bytes * 1000 / ms / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_trace_gives_address_and_country() {
        let body = "fl=12f\nh=www.cloudflare.com\nip=203.0.113.7\nloc=dk\ncolo=CPH\n";
        assert_eq!(
            parse_trace("cloudflare", body),
            (Some("203.0.113.7".to_string()), Some("DK".to_string()))
        );
    }

    #[test]
    fn trace_rejects_garbage_lines() {
        // Чужой ответ: строки с мусором отбрасываются, а не попадают в окно.
        assert_eq!(parse_trace("cloudflare", "ip=<script>loc=RU"), (None, None));
        assert_eq!(
            parse_trace("cloudflare", "ip=999.1.1.1\nloc=NLD"),
            (None, None)
        );
        assert_eq!(parse_trace("cloudflare", ""), (None, None));
        // Правильные строки ищутся только с начала строки.
        assert_eq!(
            parse_trace("cloudflare", "xip=1.2.3.4\nloc=RU"),
            (None, Some("RU".to_string()))
        );
        // Неизвестный источник — нет ответа, а не выдумка.
        assert_eq!(parse_trace("кто-то", "ip=1.2.3.4"), (None, None));
    }

    #[test]
    fn sypexgeo_json_gives_address_and_country() {
        let body = r#"{"ip":"203.0.113.7","country":{"iso":"ru"},"error":""}"#;
        assert_eq!(
            parse_trace("sypexgeo", body),
            (Some("203.0.113.7".to_string()), Some("RU".to_string()))
        );
        // Без страны — что есть; мусор в адресе и стране отбрасывается.
        assert_eq!(
            parse_trace("sypexgeo", r#"{"ip":"198.51.100.2"}"#),
            (Some("198.51.100.2".to_string()), None)
        );
        assert_eq!(
            parse_trace(
                "sypexgeo",
                r#"{"ip":"не адрес","country":{"iso":"Россия"}}"#
            ),
            (None, None)
        );
        assert_eq!(parse_trace("sypexgeo", "<html>ошибка</html>"), (None, None));
    }

    #[test]
    fn ipwho_json_needs_success_and_gives_both() {
        let body = r#"{"ip":"198.51.100.23","success":true,"country_code":"NL"}"#;
        assert_eq!(
            parse_trace("ipwho.is", body),
            (Some("198.51.100.23".to_string()), Some("NL".to_string()))
        );
        // Отказ источника и мусор не проходят за ответ.
        assert_eq!(
            parse_trace("ipwho.is", r#"{"success":false,"ip":"1.2.3.4"}"#),
            (None, None)
        );
        assert_eq!(
            parse_trace(
                "ipwho.is",
                r#"{"success":true,"ip":"999.9.9.9","country_code":"NLD"}"#
            ),
            (None, None)
        );
    }

    #[test]
    fn short_or_fast_samples_do_not_show_speed() {
        assert_eq!(kbps(32 * 1024, 1_000), None);
        assert_eq!(kbps(1024 * 1024, 400), None);
        assert_eq!(kbps(1024 * 1024, 2_000), Some(512));
        assert_eq!(kbps(0, 0), None);
    }
}
