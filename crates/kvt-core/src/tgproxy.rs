//! Прокси для Telegram Desktop (tg-ws-proxy-rs) в режимах «Zapret» и «Гибрид»:
//! аргументы запуска, домены Cloudflare для медиа и правила маршрутизации.
//!
//! Telegram Desktop подключается к прокси на `127.0.0.1`, а прокси ведёт тот же
//! зашифрованный трафик через WebSocket к `kwsN.web.telegram.org` — адреса Telegram,
//! закрытые по IP, ему не нужны. Фото и видео идут через домены за Cloudflare.

use crate::routing::{Action, Layer, Matcher, Rule};
use serde::{Deserialize, Serialize};

/// Порт по умолчанию — как у tg-ws-proxy и у всех программ на его основе: ссылка
/// `tg://proxy`, которую человек однажды принял в Telegram, остаётся верной.
pub const PORT: u16 = 1443;

/// Откуда Flowseal раздаёт список доменов Cloudflare (имена зашифрованы сдвигом).
pub const DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt";

/// Запасной список — тот же, что встроен в tg-ws-proxy-rs 2.7.0 и в оригинал.
pub const FALLBACK_ENCODED: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
];

/// Больше доменов не берём: список чужой, а каждый домен — правило маршрутизации.
const MAX_DOMAINS: usize = 32;

/// Куда прокси открывает прямой WebSocket (`kwsN.web.telegram.org` на этот адрес):
/// DC 2 и 4, как в tg-ws-proxy Flowseal. Остальные DC идут через Cloudflare.
pub const DC_IPS: &[(u8, &str)] = &[(2, "149.154.167.220"), (4, "149.154.167.220")];

/// Номера дата-центров Telegram: прокси ходит на `kws1…kws5` и `kwsN-1` (медиа).
const DCS: std::ops::RangeInclusive<u8> = 1..=5;

/// Расшифровка имени из списка Flowseal: буквы сдвинуты вперёд на число букв в
/// имени, настоящий суффикс `.co.uk` записан как `.com`.
pub fn deobfuscate(encoded: &str) -> Option<String> {
    let prefix = encoded.trim().strip_suffix(".com")?;
    let n = prefix.chars().filter(char::is_ascii_alphabetic).count() as u8 % 26;
    let shift = |c: char, base: u8| char::from((c as u8 - base + 26 - n) % 26 + base);
    let decoded: String = prefix
        .chars()
        .map(|c| match c {
            'a'..='z' => shift(c, b'a'),
            'A'..='Z' => shift(c, b'A'),
            _ => c,
        })
        .collect();
    Some(format!("{}.co.uk", decoded.to_ascii_lowercase()))
}

/// Домены из ответа Flowseal: строки `#` и пустые пропускаются, имена проверяются,
/// повторы убираются. Пустой итог — повод взять запасной список.
pub fn parse_domains(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(domain) = deobfuscate(line) else {
            continue;
        };
        if crate::zapret::valid_domain(&domain) && !out.contains(&domain) {
            out.push(domain);
        }
        if out.len() == MAX_DOMAINS {
            break;
        }
    }
    out
}

pub fn fallback_domains() -> Vec<String> {
    FALLBACK_ENCODED
        .iter()
        .filter_map(|d| deobfuscate(d))
        .collect()
}

/// Имена, к которым прокси подключается напрямую к Telegram.
pub fn telegram_hosts() -> Vec<String> {
    DCS.flat_map(|n| {
        [
            format!("kws{n}.web.telegram.org"),
            format!("kws{n}-1.web.telegram.org"),
        ]
    })
    .collect()
}

/// Переменная окружения, из которой tg-ws-proxy берёт секрет. В аргументах его не
/// передаём: командную строку процесса видят Диспетчер задач, WMI и журналы
/// антивирусов и Sysmon.
pub const SECRET_ENV: &str = "TG_SECRET";

/// Префикс переменных окружения, которыми tg-ws-proxy заменяет флаги (`TG_PORT`,
/// `TG_SOCKS_ENABLED`…). Унаследованные от пользователя не передаются: иначе они
/// поменяли бы настройки прокси — например, открыли бы ещё и SOCKS-порт.
pub const ENV_PREFIX: &str = "TG_";

/// Аргументы tg-ws-proxy (секрет — в [`SECRET_ENV`]). Адрес задан явно: без `--host`
/// прокси, найдя адрес в локальной сети, слушал бы `0.0.0.0` — и им могли бы
/// пользоваться другие устройства.
pub fn args(cf_domains: &[String], log_file: &str) -> Vec<String> {
    let mut args = vec![
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        PORT.to_string(),
        // Переменные окружения с прокси системы к Telegram не относятся.
        "--no-outbound-proxy".into(),
        "--log-file".into(),
        log_file.into(),
        // Прямой путь отвечает за доли секунды; по умолчанию прокси ждёт 10 с на каждый
        // из двух адресов DC, и Telegram успевает сдаться раньше, чем прокси перейдёт на
        // запасной путь (так было при неработающем туннеле в «Сначала VPN»).
        "--ws-connect-timeout".into(),
        "4".into(),
    ];
    // Прямой WebSocket к Telegram — первым, Cloudflare — запасным путём. Без `--dc-ip`
    // прокси при заданных `--cf-domain` вообще не пробует прямой путь и гонит всё,
    // включая фото, видео и голосовые, через общие домены Cloudflare, которые
    // перегружены и рвут соединения. Значения — как по умолчанию у Flowseal.
    for (dc, ip) in DC_IPS {
        args.push("--dc-ip".into());
        args.push(format!("{dc}:{ip}"));
    }
    if !cf_domains.is_empty() {
        args.push("--cf-domain".into());
        args.push(cf_domains.join(","));
    }
    args
}

/// Ссылка, которая открывает в Telegram окно «Подключить прокси». Префикс `dd` —
/// режим со случайным дополнением пакетов, как печатает сам прокси.
pub fn link(secret: &str) -> String {
    format!("tg://proxy?server=127.0.0.1&port={PORT}&secret=dd{secret}")
}

/// Секрет — 32 шестнадцатеричных символа (16 байт).
pub fn valid_secret(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Каким путём прокси ходит к Telegram, пока работает VPN. Сам Telegram Desktop
/// всегда подключён к прокси KVT — меняется только путь прокси, и перенастраивать
/// Telegram при смене режима не нужно.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// Сначала через VPN; не отвечает — запасным путём Cloudflare мимо VPN.
    /// Переключает сам прокси, без переподключения VPN.
    VpnFirst,
    /// Всегда мимо VPN, как в режиме «Zapret» (по умолчанию). Смысл «Гибрида» — снять с
    /// сервера то, что работает и без него; Telegram с фото и видео — заметная нагрузка,
    /// а сбой сервера тогда не задевает Telegram, и наоборот.
    #[default]
    Direct,
}

/// Правила для соединений прокси, пока работает VPN. Точными именами, а не по IP:
/// у веб-версии Telegram в браузере те же адреса, и она должна идти как обычно.
/// Слой выше пресета (там Telegram отправлен в VPN), но ниже правил пользователя.
///
/// Прямой WebSocket (`kwsN.web.telegram.org`) — первая ступень прокси, домены
/// Cloudflare — запасная. Поэтому «сначала VPN» — это первая ступень через VPN, а
/// запасная мимо него: перестал отвечать VPN — прокси сам уходит на Cloudflare.
/// `hybrid = false` — режим «VPN»: обе ступени через VPN, мимо него ничего.
pub fn route_rules(cf_domains: &[String], hybrid: bool, route: Route) -> Vec<Rule> {
    let (ws, cf) = match (hybrid, route) {
        (false, _) => (Action::Proxy, Action::Proxy),
        (true, Route::VpnFirst) => (Action::Proxy, Action::Direct),
        (true, Route::Direct) => (Action::Direct, Action::Direct),
    };
    let rule = |matcher, action| Rule {
        layer: Layer::Zapret,
        matcher,
        action,
    };
    telegram_hosts()
        .into_iter()
        .map(|h| rule(Matcher::Domain(h), ws))
        .chain(
            cf_domains
                .iter()
                .map(|d| rule(Matcher::DomainSuffix(d.clone()), cf)),
        )
        .collect()
}

/// Имена, которые winws не должен трогать: стратегия с подделкой пакетов рвёт
/// WebSocket прокси (так было у Zapret-NET), а помогать тут нечему.
pub fn zapret_exclusions(cf_domains: &[String]) -> Vec<String> {
    let mut out = vec!["web.telegram.org".to_owned()];
    out.extend(cf_domains.iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{presets, RoutingPlan};

    #[test]
    fn deobfuscates_like_upstream() {
        // Сдвиг на число букв: «abc» (3 буквы) записано как «def».
        assert_eq!(deobfuscate("def.com").as_deref(), Some("abc.co.uk"));
        assert_eq!(deobfuscate("x-1y.com").as_deref(), Some("v-1w.co.uk"));
        // Пример из тестов tg-ws-proxy-rs.
        assert_eq!(deobfuscate("virkgj.com").as_deref(), Some("pclead.co.uk"));
        assert_eq!(deobfuscate("plain.org"), None);
        let fallback = fallback_domains();
        assert_eq!(fallback.len(), FALLBACK_ENCODED.len());
        assert!(fallback
            .iter()
            .all(|d| d.ends_with(".co.uk") && crate::zapret::valid_domain(d)));
    }

    #[test]
    fn list_is_cleaned() {
        let text = "# comment\n\ndef.com\ndef.com\nbad name.com\nnot-a-list\n";
        assert_eq!(parse_domains(text), ["abc.co.uk"]);
        let many: String = (0..100).map(|i| format!("d{i}.com\n")).collect();
        assert_eq!(parse_domains(&many).len(), MAX_DOMAINS);
    }

    #[test]
    fn listens_only_on_loopback() {
        let a = args(&["abc.co.uk".into()], "p.log");
        let host = a.iter().position(|x| x == "--host").unwrap();
        assert_eq!(a[host + 1], "127.0.0.1");
        // Секрет — только в окружении, не в командной строке.
        assert!(!a.iter().any(|x| x == "--secret"));
        assert!(a.windows(2).any(|w| w == ["--cf-domain", "abc.co.uk"]));
        // Прямой путь к Telegram задан всегда, иначе медиа уходят только в Cloudflare.
        assert!(a.windows(2).any(|w| w == ["--dc-ip", "2:149.154.167.220"]));
        assert!(a.windows(2).any(|w| w == ["--dc-ip", "4:149.154.167.220"]));
        assert!(!args(&[], "p.log").contains(&"--cf-domain".to_owned()));
    }

    #[test]
    fn secret_and_link() {
        let s = "00112233445566778899aabbccddeeff";
        assert!(valid_secret(s));
        assert!(!valid_secret("00112233"));
        assert!(!valid_secret("zz112233445566778899aabbccddeeff"));
        assert_eq!(
            link(s),
            "tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff"
        );
    }

    /// В гибриде прокси идёт мимо туннеля, а Telegram в браузере — нет.
    #[test]
    fn hybrid_sends_proxy_direct_but_keeps_web_telegram_in_vpn() {
        let mut plan = RoutingPlan::new(Action::Direct);
        plan.push(Rule {
            layer: Layer::Preset,
            matcher: Matcher::DomainSuffix("telegram.org".into()),
            action: Action::Proxy,
        });
        plan.extend(presets::zapret_youtube_discord());
        plan.extend(route_rules(&["abc.co.uk".into()], true, Route::Direct));
        plan.validate().unwrap();
        assert_eq!(plan.resolve_domain("kws2.web.telegram.org"), Action::Direct);
        assert_eq!(
            plan.resolve_domain("kws4-1.web.telegram.org"),
            Action::Direct
        );
        assert_eq!(plan.resolve_domain("kws2.abc.co.uk"), Action::Direct);
        assert_eq!(plan.resolve_domain("web.telegram.org"), Action::Proxy);
        assert_eq!(plan.resolve_domain("telegram.org"), Action::Proxy);
        assert!(!plan
            .zapret_hostlist()
            .iter()
            .any(|d| d.contains("telegram")));
    }

    /// «Сначала VPN»: прямая ступень прокси — в VPN, запасная (Cloudflare) — мимо.
    /// Режим «VPN»: обе в VPN.
    #[test]
    fn vpn_first_and_vpn_mode() {
        let cf = ["abc.co.uk".to_owned()];
        let plan = |hybrid, route| {
            let mut p = RoutingPlan::new(Action::Direct);
            p.extend(route_rules(&cf, hybrid, route));
            p.validate().unwrap();
            p
        };
        let first = plan(true, Route::VpnFirst);
        assert_eq!(first.resolve_domain("kws2.web.telegram.org"), Action::Proxy);
        assert_eq!(first.resolve_domain("kws2.abc.co.uk"), Action::Direct);
        let vpn = plan(false, Route::Direct);
        assert_eq!(vpn.resolve_domain("kws2.web.telegram.org"), Action::Proxy);
        assert_eq!(vpn.resolve_domain("kws2.abc.co.uk"), Action::Proxy);
    }
}
