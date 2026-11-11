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

    /// Ответ «не изменилась» (304): тела нет, но заголовки бывают. Что пришло —
    /// обновляет прежнее, чего нет — остаётся. Трафик и срок меняются вместе: они из
    /// одного заголовка. Интервал не трогаем — без заголовка в `fresh` он по умолчанию.
    pub fn refresh_from(&mut self, fresh: SubscriptionMeta) {
        if fresh.upload.is_some()
            || fresh.download.is_some()
            || fresh.total.is_some()
            || fresh.expire.is_some()
        {
            self.upload = fresh.upload;
            self.download = fresh.download;
            self.total = fresh.total;
            self.expire = fresh.expire;
        }
        for (old, new) in [
            (&mut self.title, fresh.title),
            (&mut self.support_url, fresh.support_url),
            (&mut self.web_page_url, fresh.web_page_url),
            (&mut self.announce, fresh.announce),
        ] {
            if new.is_some() {
                *old = new;
            }
        }
    }
}

/// Метки версии ответа (`ETag`, `Last-Modified`) для условного запроса: если
/// подписка не изменилась, сервер отвечает коротким 304 без тела. Значения
/// недоверенные и уходят обратно в заголовки — только видимый ASCII и короткие.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validators {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

const MAX_VALIDATOR_LEN: usize = 200;

impl Validators {
    /// `None` — сервер не дал ни одной годной метки.
    pub fn from_headers<'a>(headers: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Self> {
        let mut v = Validators::default();
        for (name, value) in headers {
            match name.to_ascii_lowercase().as_str() {
                "etag" => v.etag = header_token(value),
                "last-modified" => v.last_modified = header_token(value),
                _ => {}
            }
        }
        (v.etag.is_some() || v.last_modified.is_some()).then_some(v)
    }
}

fn header_token(value: &str) -> Option<String> {
    header_value(value, MAX_VALIDATOR_LEN)
}

/// Значение для заголовка запроса: только видимый ASCII и пробел, не длиннее `max`.
/// Для своего User-Agent и ID устройства — они уходят в заголовки как есть.
pub fn header_value(value: &str, max: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= max && value.chars().all(|c| (' '..='~').contains(&c)))
        .then(|| value.to_owned())
}

/// Что панель провайдера сказала про ID устройства (заголовки Remnawave при
/// ограничении числа устройств).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwidSignal {
    /// Ограничение включено, а клиент не прислал `x-hwid`.
    Required,
    /// Устройств у пользователя уже столько, сколько разрешено.
    LimitReached,
}

pub fn hwid_signal<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<HwidSignal> {
    let mut signal = None;
    for (name, value) in headers {
        if !value.trim().eq_ignore_ascii_case("true") {
            continue;
        }
        match name.to_ascii_lowercase().as_str() {
            "x-hwid-max-devices-reached" => return Some(HwidSignal::LimitReached),
            "x-hwid-not-supported" => signal = Some(HwidSignal::Required),
            _ => {}
        }
    }
    signal
}

/// Фильтр серверов подписки по названию: «оставить только» и «убрать». Слово
/// совпадает, если оно есть в названии (без учёта регистра) или равно коду страны
/// флага-эмодзи («NL» — для «🇳🇱 Amsterdam»).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameFilter {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keep: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drop: Vec<String>,
}

const MAX_FILTER_WORDS: usize = 30;
const MAX_FILTER_WORD: usize = 60;

impl NameFilter {
    /// Из строк, как их ввёл пользователь: слова через запятую или с новой строки.
    pub fn parse(keep: &str, drop: &str) -> Result<Self, String> {
        Ok(NameFilter {
            keep: filter_words(keep)?,
            drop: filter_words(drop)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.keep.is_empty() && self.drop.is_empty()
    }

    pub fn allows(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        let flag = crate::flag::split_flags(name).flag;
        let hit = |w: &String| lower.contains(w.as_str()) || flag.as_deref() == Some(w.as_str());
        (self.keep.is_empty() || self.keep.iter().any(hit)) && !self.drop.iter().any(hit)
    }
}

fn filter_words(text: &str) -> Result<Vec<String>, String> {
    let mut words: Vec<String> = Vec::new();
    for w in text.split([',', ';', '\n']) {
        let w = w.trim().to_lowercase();
        if w.is_empty() || words.contains(&w) {
            continue;
        }
        if w.chars().count() > MAX_FILTER_WORD || w.chars().any(char::is_control) {
            return Err(crate::trf!(
                "Слово фильтра длиннее {MAX_FILTER_WORD} символов или с непечатаемыми символами.",
                "A filter word is longer than {MAX_FILTER_WORD} characters or has non-printable characters."
            ));
        }
        words.push(w);
    }
    if words.len() > MAX_FILTER_WORDS {
        return Err(crate::trf!(
            "В фильтре больше {MAX_FILTER_WORDS} слов.",
            "The filter has more than {MAX_FILTER_WORDS} words."
        ));
    }
    Ok(words)
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

/// Клиенты, чьи ссылки «добавить подписку» KVT разворачивает в исходный адрес.
const APP_SCHEMES: &[&str] = &[
    "happ",
    "incy",
    "v2raytun",
    "hiddify",
    "v2rayng",
    "v2box",
    "streisand",
    "clash",
    "sing-box",
];

/// Ссылка вида `happ://add/https://…`, `incy://import/…`, `v2raytun://import/…`,
/// `hiddify://import/…` или `…://install-config?url=…` → исходный адрес подписки.
/// `Ok(None)` — это не ссылка клиента (обычный адрес или ключи), `Err` — ссылка
/// клиента, из которой адрес не достать (например, зашифрованная `happ://crypt…`).
pub fn unwrap_app_link(raw: &str) -> Result<Option<String>, &'static str> {
    let raw = raw.trim();
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Ok(None);
    };
    let scheme = scheme.to_ascii_lowercase();
    if !APP_SCHEMES.contains(&scheme.as_str()) {
        return Ok(None);
    }
    if rest.to_ascii_lowercase().starts_with("crypt") {
        return Err(crate::i18n::tr("Это зашифрованная ссылка Happ — её может прочитать только Happ. Попросите у провайдера обычную ссылку на подписку (https://…).", "This is an encrypted Happ link — only Happ can read it. Ask your provider for a regular subscription link (https://…)."));
    }
    let decode = |s: &str| {
        percent_encoding::percent_decode_str(s)
            .decode_utf8_lossy()
            .into_owned()
    };
    // `…?url=<адрес>` (install-config, import-remote-profile) — адрес в параметре.
    let from_query = rest.split_once('?').and_then(|(_, q)| {
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| k.eq_ignore_ascii_case("url"))
            .map(|(_, v)| decode(v.split('#').next().unwrap_or(v)))
    });
    // `add/<адрес>`, `import/<адрес>` — адрес целиком после действия.
    let from_path = || {
        let lower = rest.to_ascii_lowercase();
        ["add/", "import/", "install-sub/", "subscription/"]
            .iter()
            .find(|p| lower.starts_with(*p))
            .map(|p| rest[p.len()..].to_owned())
            .map(|r| if r.contains("://") { r } else { decode(&r) })
    };
    let url = from_query
        .or_else(from_path)
        .map(|u| u.trim().to_owned())
        .filter(|u| {
            u.to_ascii_lowercase().starts_with("https://")
                || u.to_ascii_lowercase().starts_with("http://")
        });
    match url {
        Some(u) => Ok(Some(u)),
        None => Err(crate::i18n::tr("Не удалось достать адрес подписки из ссылки приложения. Скопируйте обычную ссылку (https://…) в личном кабинете провайдера.", "Couldn't get the subscription address from the app link. Copy the regular link (https://…) from your provider's account page.")),
    }
}

/// Больше ссылок на подписки за одну вставку не берём: каждая — сетевой запрос.
pub const MAX_INPUT_URLS: usize = 20;

/// Вставка, разложенная на адреса подписок и всё остальное (ключи, base64, JSON).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SplitInput {
    /// Адреса подписок (`https://…`, `http://…`, ссылки «добавить в приложение») в
    /// порядке вставки, без повторов. Проверка схемы — дело загрузчика.
    pub urls: Vec<String>,
    /// Остальное: ссылки на серверы, base64 или конфиги. Пусто — ключей во вставке нет.
    pub rest: String,
}

/// Раскладывает вставку пользователя. Понимает несколько ссылок на подписки сразу,
/// ссылку внутри текста («Ваша подписка: https://…», кавычки, скобки) и смесь
/// подписок с ключами. base64 и JSON целиком уходят в `rest` как есть.
pub fn split_input(input: &str) -> SplitInput {
    let trimmed = input.trim().trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') || !trimmed.contains("://") {
        return SplitInput {
            urls: Vec::new(),
            rest: trimmed.to_owned(),
        };
    }
    let mut urls: Vec<String> = Vec::new();
    let mut keys: Vec<&str> = Vec::new();
    for line in trimmed.lines().map(str::trim).filter(|l| !l.is_empty()) {
        // Ссылка на сервер занимает строку целиком: в названии после `#` бывают пробелы.
        if starts_with_server_scheme(line) {
            keys.push(line);
            continue;
        }
        // Ключ посреди текста («Ключ: vless://…») — до конца строки.
        if let Some(at) = server_link_start(line) {
            keys.push(&line[at..]);
        }
        for token in line.split_whitespace() {
            const QUOTES: &str = "\"'«»<>()[]{}`";
            let token = token
                .trim_start_matches(|c: char| QUOTES.contains(c))
                .trim_end_matches(|c: char| QUOTES.contains(c) || ".,;!?:".contains(c));
            if is_subscription_address(token) && !urls.iter().any(|u| u == token) {
                urls.push(token.to_owned());
            }
        }
    }
    urls.truncate(MAX_INPUT_URLS);
    // Ни одного адреса подписки — вставка как есть (её разберёт парсер ключей).
    let rest = if urls.is_empty() {
        trimmed.to_owned()
    } else {
        keys.join("\n")
    };
    SplitInput { urls, rest }
}

/// Где в строке текста начинается ссылка на сервер (после пробела).
fn server_link_start(line: &str) -> Option<usize> {
    line.match_indices(char::is_whitespace)
        .map(|(i, c)| i + c.len())
        .find(|&i| starts_with_server_scheme(&line[i..]))
}

/// Строка начинается со ссылки на сервер (`vless://`, `ss://`, …), а не на подписку.
fn starts_with_server_scheme(line: &str) -> bool {
    let Some((scheme, _)) = line.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !is_subscription_address(line)
}

fn is_subscription_address(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        // `https://логин:пароль@адрес:порт` — HTTP-прокси, а не подписка.
        return lower.len() > "https://".len() && !crate::parser::is_http_proxy_link(token);
    }
    lower
        .split_once("://")
        .is_some_and(|(scheme, _)| APP_SCHEMES.contains(&scheme))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_proxy_link_is_a_key_not_a_subscription() {
        let got =
            split_input("https://sub.example.com/abc\nhttp://u:p@proxy.example.com:8080#Прокси");
        assert_eq!(got.urls, ["https://sub.example.com/abc"]);
        assert_eq!(got.rest, "http://u:p@proxy.example.com:8080#Прокси");
        // Одна прокси-ссылка — подписок нет, вся вставка уходит в ключи.
        let got = split_input("https://u:p@proxy.example.com:8443");
        assert!(got.urls.is_empty());
    }

    #[test]
    fn single_url_stays_url() {
        let got = split_input("  https://sub.example.com/abc?x=1 \n");
        assert_eq!(got.urls, ["https://sub.example.com/abc?x=1"]);
        assert!(got.rest.is_empty());
    }

    #[test]
    fn url_inside_text_is_found() {
        let got = split_input("Ваша подписка: «https://sub.example.com/abc». Срок — 30 дней.");
        assert_eq!(got.urls, ["https://sub.example.com/abc"]);
        assert!(got.rest.is_empty());
    }

    #[test]
    fn several_urls_and_keys_are_split() {
        let input = "https://a.example.com/1\nhappy text\nhttps://b.example.com/2 https://a.example.com/1\n\
                     vless://id@h:443?type=tcp#Сервер с пробелами\nКлюч: trojan://p@h:443#b\n\
                     happ://add/https://c.example.com/3";
        let got = split_input(input);
        assert_eq!(
            got.urls,
            [
                "https://a.example.com/1",
                "https://b.example.com/2",
                "happ://add/https://c.example.com/3"
            ]
        );
        assert_eq!(
            got.rest,
            "vless://id@h:443?type=tcp#Сервер с пробелами\ntrojan://p@h:443#b"
        );
    }

    #[test]
    fn keys_base64_and_json_are_left_alone() {
        let keys = "vless://id@h:443#a\ntrojan://p@h:443#b";
        assert_eq!(split_input(keys).rest, keys);
        assert!(split_input(keys).urls.is_empty());
        let b64 = "dmxlc3M6Ly9pZEBoOjQ0MyNh";
        assert_eq!(split_input(b64).rest, b64);
        // В JSON бывают адреса (`https://…` в remarks) — это не подписка.
        let json = r#"{"outbounds":[],"remarks":"https://example.com"}"#;
        assert_eq!(split_input(json).rest, json);
        assert!(split_input(json).urls.is_empty());
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for input in [
            "://",
            "https://",
            "a://b://c",
            "\u{feff}",
            "https:// x",
            &"https://a/ ".repeat(500),
        ] {
            let got = split_input(input);
            assert!(got.urls.len() <= MAX_INPUT_URLS);
        }
    }

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

    #[test]
    fn app_links_unwrap_to_subscription_url() {
        let url = "https://sub.example.com/abc?x=1";
        for link in [
            format!("happ://add/{url}"),
            format!("incy://import/{url}"),
            format!("INCY://add/{url}"),
            format!("v2raytun://import/{url}"),
            format!("hiddify://import/{url}#Имя"),
            "clash://install-config?url=https%3A%2F%2Fsub.example.com%2Fabc%3Fx%3D1".to_owned(),
            "sing-box://import-remote-profile?url=https%3A%2F%2Fsub.example.com%2Fabc%3Fx%3D1#n"
                .to_owned(),
        ] {
            let got = unwrap_app_link(&link).unwrap().unwrap();
            assert!(got.starts_with(url), "{link} -> {got}");
        }
    }

    #[test]
    fn other_input_is_left_alone_or_explained() {
        assert_eq!(unwrap_app_link("https://sub.example.com/x"), Ok(None));
        assert_eq!(unwrap_app_link("vless://id@h:1"), Ok(None));
        assert!(unwrap_app_link("happ://crypt3/AbCd").is_err());
        assert!(unwrap_app_link("happ://add/not-a-url").is_err());
    }

    #[test]
    fn validators_from_headers_reject_bad_values() {
        let v = Validators::from_headers([
            ("ETag", "W/\"abc-123\""),
            ("Last-Modified", " Wed, 11 Nov 2026 10:00:00 GMT "),
        ])
        .unwrap();
        assert_eq!(v.etag.as_deref(), Some("W/\"abc-123\""));
        assert_eq!(
            v.last_modified.as_deref(),
            Some("Wed, 11 Nov 2026 10:00:00 GMT")
        );

        // Переводы строк, не-ASCII и слишком длинное — не берём: уйдёт обратно в заголовок.
        let long = "x".repeat(MAX_VALIDATOR_LEN + 1);
        assert_eq!(
            Validators::from_headers([(
                "etag",
                "\"a\"
X-Evil: 1"
            )]),
            None
        );
        assert_eq!(Validators::from_headers([("etag", "\"тег\"")]), None);
        assert_eq!(Validators::from_headers([("etag", long.as_str())]), None);
        assert_eq!(Validators::from_headers([("etag", "  ")]), None);
        assert_eq!(
            Validators::from_headers([("content-type", "text/plain")]),
            None
        );
    }

    #[test]
    fn not_modified_keeps_what_was_not_sent() {
        let mut meta = parse_headers([
            ("profile-title", "Провайдер"),
            (
                "subscription-userinfo",
                "upload=1; download=2; total=100; expire=1767225600",
            ),
            ("profile-update-interval", "24"),
        ]);
        // 304 без заголовков — всё как было.
        meta.refresh_from(SubscriptionMeta::default());
        assert_eq!(meta.title.as_deref(), Some("Провайдер"));
        assert_eq!(meta.used_bytes(), Some(3));
        assert_eq!(meta.update_interval, Duration::from_secs(24 * 3600));
        // 304 со свежим трафиком — трафик новый, остальное прежнее.
        meta.refresh_from(parse_headers([(
            "subscription-userinfo",
            "upload=5; download=5; total=100",
        )]));
        assert_eq!(meta.used_bytes(), Some(10));
        assert_eq!(meta.expire, None);
        assert_eq!(meta.title.as_deref(), Some("Провайдер"));
        assert_eq!(meta.update_interval, Duration::from_secs(24 * 3600));
    }

    #[test]
    fn name_filter_keeps_and_drops() {
        let f = NameFilter::parse("NL, германия", "резерв").unwrap();
        assert!(f.allows("🇳🇱 Amsterdam"));
        assert!(f.allows("Германия 1"));
        assert!(!f.allows("🇳🇱 Amsterdam резерв"));
        assert!(!f.allows("🇫🇮 Helsinki"));
        // Пустой «оставить» — всё, кроме убранного.
        let f = NameFilter::parse("", "Test;\nTEST").unwrap();
        assert_eq!(f.drop, ["test"]);
        assert!(f.allows("Рабочий") && !f.allows("Test server"));
        assert!(NameFilter::parse(" , ;", "").unwrap().is_empty());
    }

    #[test]
    fn name_filter_rejects_bad_input() {
        assert!(NameFilter::parse(&"ы".repeat(61), "").is_err());
        assert!(NameFilter::parse("a\u{7}b", "").is_err());
        let many: Vec<String> = (0..31).map(|i| format!("w{i}")).collect();
        assert!(NameFilter::parse("", &many.join(",")).is_err());
    }

    #[test]
    fn header_values_and_hwid_signals() {
        assert_eq!(
            header_value("  Happ/3.6.1 ", 200).as_deref(),
            Some("Happ/3.6.1")
        );
        assert!(header_value("кириллица", 200).is_none());
        assert!(header_value("a\r\nX-Evil: 1", 200).is_none());
        assert!(header_value(&"a".repeat(201), 200).is_none());
        assert!(header_value("", 200).is_none());
        assert_eq!(
            hwid_signal([("X-HWID-Not-Supported", "true")]),
            Some(HwidSignal::Required)
        );
        assert_eq!(
            hwid_signal([
                ("x-hwid-not-supported", "true"),
                ("x-hwid-max-devices-reached", "TRUE")
            ]),
            Some(HwidSignal::LimitReached)
        );
        assert_eq!(
            hwid_signal([("x-hwid-active", "true"), ("x-hwid-not-supported", "false")]),
            None
        );
    }
}
