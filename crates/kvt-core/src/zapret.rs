//! zapret из [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).
//!
//! Стратегии Flowseal — это `.bat`-файлы. Мы их не запускаем: они вызывают
//! `service.bat`, меняют настройки TCP и убивают чужие процессы. Вместо этого
//! из файла извлекаются аргументы `winws.exe`, каждый флаг сверяется с белым
//! списком, а пути подставляет служба — только свои каталоги. winws работает от
//! SYSTEM, поэтому лишний флаг (например, `--debug=@файл`) — это запись в любой файл.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Версия релиза Flowseal, с которым собран KVT (`scripts/fetch-zapret.ps1`).
pub const FLOWSEAL_VERSION: &str = "1.10.4";

/// Архив релиза, с которым собран KVT: им «Переустановить» восстанавливает комплект.
pub const ARCHIVE_SHA256: &str = "291af673bd0238506f9548e0e94ca0abf244000f4c9a06960544fb01c5f97b34";
pub const RELEASES_API: &str =
    "https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest";
const DOWNLOAD_PREFIX: &str =
    "https://github.com/Flowseal/zapret-discord-youtube/releases/download/";

pub fn archive_url(version: &str) -> String {
    format!("{DOWNLOAD_PREFIX}{version}/zapret-discord-youtube-{version}.zip")
}

/// Исполняемые файлы комплекта: они работают от SYSTEM.
pub const BINARIES: &[&str] = &[
    "winws.exe",
    "WinDivert.dll",
    "WinDivert64.sys",
    "cygwin1.dll",
];

/// Проверенные SHA-256 исполняемых файлов. Служба сверяет их перед каждым запуском,
/// а обновление Flowseal принимает новые файлы, только если их хэш есть здесь:
/// новые исполняемые файлы приходят с обновлением KVT, а не из интернета.
pub const BINARY_HASHES: &[(&str, &str)] = &[
    (
        "winws.exe",
        "affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188",
    ),
    (
        "WinDivert.dll",
        "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
    ),
    (
        "WinDivert64.sys",
        "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
    ),
    (
        "cygwin1.dll",
        "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b",
    ),
];

pub fn binary_known(name: &str, sha256: &str) -> bool {
    BINARY_HASHES
        .iter()
        .any(|(n, h)| n.eq_ignore_ascii_case(name) && h.eq_ignore_ascii_case(sha256))
}

/// Версия Flowseal: только цифры и точки (`1.10.4`).
pub fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 20
        && v.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `a` новее `b` (по числам: 1.10.4 новее 1.9.9).
pub fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parts(a) > parts(b)
}

/// Последний релиз Flowseal по ответу API GitHub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub version: String,
    pub zip_url: String,
    pub sha256: String,
}

/// Разбор `releases/latest`. Ссылка — только на релизы Flowseal, хэш — из `digest`
/// (GitHub считает его сам при загрузке файла).
pub fn parse_release(json: &[u8]) -> Result<Release, String> {
    #[derive(Deserialize)]
    struct Asset {
        name: String,
        browser_download_url: String,
        digest: Option<String>,
    }
    #[derive(Deserialize)]
    struct Raw {
        tag_name: String,
        assets: Vec<Asset>,
    }
    let raw: Raw = serde_json::from_slice(json)
        .map_err(|e| crate::trf!("ответ GitHub: {e}", "GitHub response: {e}"))?;
    let version = raw.tag_name.trim_start_matches('v').to_owned();
    if !valid_version(&version) {
        return Err(crate::trf!(
            "непонятная версия «{}»",
            "unrecognized version “{}”",
            raw.tag_name
        ));
    }
    let expected = archive_url(&version);
    let asset = raw
        .assets
        .into_iter()
        .find(|a| a.name.ends_with(".zip") && a.browser_download_url == expected)
        .ok_or(crate::i18n::tr(
            "в релизе нет архива zip",
            "the release has no zip archive",
        ))?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(crate::i18n::tr(
            "у архива нет SHA-256 от GitHub",
            "the archive has no SHA-256 from GitHub",
        ))?
        .to_ascii_lowercase();
    Ok(Release {
        version,
        zip_url: asset.browser_download_url,
        sha256,
    })
}

/// Порядок перебора при автоподборе — как в меню Flowseal: основная, ALT…, FAKE TLS, SIMPLE FAKE.
pub const PREFERRED_ORDER: &[&str] = &[
    "general",
    "general (ALT)",
    "general (ALT2)",
    "general (ALT3)",
    "general (ALT4)",
    "general (ALT6)",
    "general (ALT7)",
    "general (ALT8)",
    "general (ALT9)",
    "general (ALT10)",
    "general (ALT11)",
    "general (ALT12)",
    "general (ALT13)",
    "general (FAKE TLS AUTO)",
    "general (FAKE TLS AUTO ALT)",
    "general (FAKE TLS AUTO ALT2)",
    "general (FAKE TLS AUTO ALT3)",
    "general (SIMPLE FAKE)",
    "general (SIMPLE FAKE ALT)",
    "general (SIMPLE FAKE ALT2)",
    "general (EXP)",
    "general (ALT5)",
];

/// Игровой фильтр Flowseal: обход для всех портов выше 1024 (по умолчанию выключен).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GameFilter {
    #[default]
    Off,
    Tcp,
    Udp,
    All,
}

impl GameFilter {
    /// Выключенный фильтр Flowseal задаёт портом 12 — на нём ничего не работает.
    fn tcp(self) -> &'static str {
        match self {
            GameFilter::Tcp | GameFilter::All => "1024-65535",
            _ => "12",
        }
    }

    fn udp(self) -> &'static str {
        match self {
            GameFilter::Udp | GameFilter::All => "1024-65535",
            _ => "12",
        }
    }
}

/// Флаги winws, которые встречаются в стратегиях Flowseal. Остальные отвергаются.
const ALLOWED_FLAGS: &[&str] = &[
    "--new",
    "--wf-tcp",
    "--wf-udp",
    "--filter-tcp",
    "--filter-udp",
    "--filter-l3",
    "--filter-l7",
    "--hostlist",
    "--hostlist-exclude",
    "--hostlist-domains",
    "--hostlist-exclude-domains",
    "--ipset",
    "--ipset-exclude",
    "--ip-id",
    "--dpi-desync",
    "--dpi-desync-repeats",
    "--dpi-desync-fooling",
    "--dpi-desync-cutoff",
    "--dpi-desync-any-protocol",
    "--dpi-desync-badseq-increment",
    "--dpi-desync-split-pos",
    "--dpi-desync-split-seqovl",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-hostfakesplit-mod",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-tls-mod",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp",
];

/// Флаги, значение которых может быть файлом из `bin` или `lists`.
const FILE_FLAGS: &[&str] = &[
    "--hostlist",
    "--hostlist-exclude",
    "--ipset",
    "--ipset-exclude",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp",
];

const BIN: &str = "%BIN%";
const LISTS: &str = "%LISTS%";
const GAME_TCP: &str = "%GameFilterTCP%";
const GAME_UDP: &str = "%GameFilterUDP%";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ZapretError {
    #[error(
        "{}",
        crate::i18n::tr(
            "в файле стратегии нет запуска winws.exe",
            "the strategy file doesn't run winws.exe"
        )
    )]
    NoWinws,
    #[error(
        "{}",
        crate::i18n::tr("незакрытая кавычка в аргументах", "unclosed quote in arguments")
    )]
    Quote,
    #[error("{}", crate::trf!("флаг «{}» не разрешён", "flag “{}” isn't allowed", .0))]
    Flag(String),
    #[error("{}", crate::trf!("недопустимое значение «{}» у флага {}", "invalid value “{}” for flag {}", .1, .0))]
    Value(String, String),
    #[error("{}", crate::trf!("неизвестная стратегия «{}»", "unknown strategy “{}”", .0))]
    UnknownStrategy(String),
    #[error("{}", crate::trf!("недопустимый домен «{}»", "invalid domain “{}”", .0))]
    Domain(String),
}

/// Стратегия: id — имя файла без `.bat` (`general (ALT4)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Strategy {
    pub id: String,
    pub title: String,
    /// Flowseal не рекомендует (пометка `NOT RECOMMENDED` в файле).
    pub recommended: bool,
    /// Использует `fooling=ts` — нужны включённые TCP timestamps.
    pub needs_timestamps: bool,
    /// Аргументы с подстановками `%BIN%`, `%LISTS%`, `%GameFilter…%`.
    #[serde(skip)]
    pub args: Vec<String>,
}

/// Название для интерфейса: `general` → «Основная», `general (ALT4)` → «ALT4».
pub fn title(id: &str) -> String {
    match id
        .strip_prefix("general (")
        .and_then(|s| s.strip_suffix(')'))
    {
        Some(inner) => inner.to_owned(),
        None if id == "general" => crate::i18n::tr("Основная", "Main").to_owned(),
        None => id.to_owned(),
    }
}

/// Безопасное имя стратегии: буквы, цифры, пробел, скобки — без путей.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '(' | ')' | '_' | '-'))
}

/// Склеивает строки с `^` в конце и берёт всё после `winws.exe"`.
fn command_tail(text: &str) -> Option<String> {
    let mut joined = String::new();
    let mut collecting = false;
    for line in text.lines() {
        let line = line.trim_end();
        if !collecting {
            let Some(pos) = line.find("winws.exe\"") else {
                continue;
            };
            collecting = true;
            joined.push_str(&line[pos + "winws.exe\"".len()..]);
        } else {
            joined.push(' ');
            joined.push_str(line);
        }
        match joined.strip_suffix('^') {
            Some(rest) => joined.truncate(rest.len()),
            None => return Some(joined),
        }
    }
    collecting.then_some(joined)
}

/// Разбор как в cmd: кавычки группируют, `^` экранирует следующий символ.
fn tokenize(s: &str) -> Result<Vec<String>, ZapretError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '^' if !quoted => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if quoted {
        return Err(ZapretError::Quote);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Значение без путей и спецсимволов cmd: порты, числа, режимы, `sni=ya.ru`, `!`.
fn safe_plain(value: &str) -> bool {
    value
        .replace(GAME_TCP, "")
        .replace(GAME_UDP, "")
        .chars()
        .all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | ',' | ':' | '=' | '+' | '_' | '-' | '!')
        })
}

fn check_arg(arg: &str) -> Result<(), ZapretError> {
    let (flag, value) = match arg.split_once('=') {
        Some((f, v)) => (f, Some(v)),
        None => (arg, None),
    };
    if !ALLOWED_FLAGS.contains(&flag) {
        return Err(ZapretError::Flag(flag.to_owned()));
    }
    let Some(value) = value else {
        return Ok(());
    };
    let bad = || ZapretError::Value(flag.to_owned(), value.to_owned());
    if let Some(name) = value
        .strip_prefix(BIN)
        .or_else(|| value.strip_prefix(LISTS))
    {
        return if FILE_FLAGS.contains(&flag) && safe_file_name(name) {
            Ok(())
        } else {
            Err(bad())
        };
    }
    if safe_plain(value) {
        Ok(())
    } else {
        Err(bad())
    }
}

/// Стратегия из текста `.bat`. Любой неизвестный флаг или путь — ошибка целиком.
pub fn parse_bat(id: &str, text: &str) -> Result<Strategy, ZapretError> {
    if !valid_id(id) {
        return Err(ZapretError::UnknownStrategy(id.to_owned()));
    }
    let tail = command_tail(text).ok_or(ZapretError::NoWinws)?;
    let args = tokenize(&tail)?;
    if args.is_empty() {
        return Err(ZapretError::NoWinws);
    }
    for arg in &args {
        check_arg(arg)?;
    }
    let needs_timestamps = args.iter().any(|a| {
        a.strip_prefix("--dpi-desync-fooling=")
            .is_some_and(|v| v.split(',').any(|f| f == "ts"))
    });
    Ok(Strategy {
        id: id.to_owned(),
        title: title(id),
        recommended: !text.contains("NOT RECOMMENDED"),
        needs_timestamps,
        args,
    })
}

/// Сортировка для интерфейса и автоподбора: порядок Flowseal, неизвестные — в конце.
pub fn sort(strategies: &mut [Strategy]) {
    let rank = |id: &str| {
        PREFERRED_ORDER
            .iter()
            .position(|p| *p == id)
            .unwrap_or(PREFERRED_ORDER.len())
    };
    strategies.sort_by(|a, b| {
        (!a.recommended, rank(&a.id), &a.id).cmp(&(!b.recommended, rank(&b.id), &b.id))
    });
}

pub struct RenderContext<'a> {
    /// Каталог `bin` с завершающим разделителем.
    pub bin: &'a str,
    /// Каталог списков с завершающим разделителем.
    pub lists: &'a str,
    pub game: GameFilter,
    /// Индекс сетевого интерфейса. В гибриде winws работает только на физическом
    /// интерфейсе и не трогает пакеты внутри TUN.
    pub interface: Option<u32>,
}

/// Готовые аргументы winws.
///
/// Наши исключения добавляются в профили, где их нет: `ipset-exclude-user.txt` (адреса
/// VPN-серверов) — в каждый, `list-exclude-user.txt` (SNI серверов, «Никогда не
/// трогать», прокси Telegram) — в профили, которые и так выбираются по имени хоста.
/// У Flowseal они есть не везде: например, в ALT9 профиль `--hostlist=list-google.txt`
/// с `hostfakesplit` идёт без исключений — и рукопожатие с VPN-сервером, SNI которого
/// совпал с доменом из списка, попадало под стратегию.
pub fn render(strategy: &Strategy, ctx: &RenderContext<'_>) -> Vec<String> {
    let mut out = Vec::with_capacity(strategy.args.len() + 16);
    if let Some(index) = ctx.interface {
        out.push(format!("--wf-iface={index}"));
    }
    let args: Vec<String> = strategy
        .args
        .iter()
        .map(|a| {
            a.replace(BIN, ctx.bin)
                .replace(LISTS, ctx.lists)
                .replace(GAME_TCP, ctx.game.tcp())
                .replace(GAME_UDP, ctx.game.udp())
        })
        .collect();
    let hostlist_exclude = format!("--hostlist-exclude={}list-exclude-user.txt", ctx.lists);
    let ipset_exclude = format!("--ipset-exclude={}ipset-exclude-user.txt", ctx.lists);
    // Профиль — от первого фильтра до `--new`; `--wf-*` перед ним — общие параметры.
    let mut profile: Vec<String> = Vec::new();
    let close = |profile: &mut Vec<String>, out: &mut Vec<String>| {
        if profile.iter().any(|a| a.starts_with("--filter-")) {
            // По адресу — везде: имя хоста для этого не нужно.
            if !profile.contains(&ipset_exclude) {
                profile.push(ipset_exclude.clone());
            }
            // По имени — только туда, где профиль и так выбирается по имени хоста.
            // Непустой хостлист (даже исключающий) делает профиль недоступным для
            // трафика без имени хоста: голос Discord по UDP, игровой фильтр по IP
            // перестали бы обрабатываться.
            let by_name = profile.iter().any(|a| {
                a.starts_with("--hostlist=")
                    || a.starts_with("--hostlist-domains=")
                    || a.starts_with("--hostlist-exclude")
            });
            if by_name && !profile.contains(&hostlist_exclude) {
                profile.push(hostlist_exclude.clone());
            }
        }
        out.append(profile);
    };
    for a in args {
        if a == "--new" {
            close(&mut profile, &mut out);
            out.push(a);
        } else if a.starts_with("--wf-") && profile.is_empty() {
            out.push(a);
        } else {
            profile.push(a);
        }
    }
    close(&mut profile, &mut out);
    out
}

/// Домен для списка winws: только буквы, цифры, точки и дефисы, без переводов строк.
pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && !d.starts_with('.')
        && !d.ends_with('.')
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Заглушка Flowseal: пустой список winws понимает как «всё», поэтому пустым он не бывает.
pub const EMPTY_HOSTLIST: &str = "domain.example.abc";
pub const EMPTY_IPSET: &str = "203.0.113.113/32";

/// Пользовательские списки (`*-user.txt`), которые стратегии Flowseal подключают сами.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLists {
    /// Домены, которые идут через zapret (из RoutingPlan).
    pub general: String,
    /// Домены VPN-серверов — winws их не трогает.
    pub exclude: String,
    /// IP VPN-серверов — winws их не трогает.
    pub ipset_exclude: String,
}

/// `exclude` — домены, которые пользователь исключил из zapret; к ним добавляются
/// домены VPN-серверов.
pub fn user_lists(
    domains: &[String],
    exclude: &[String],
    server_domains: &[String],
    server_ips: &[std::net::IpAddr],
) -> Result<UserLists, ZapretError> {
    let join = |items: &[String], empty: &str| {
        if items.is_empty() {
            format!("{empty}\n")
        } else {
            items.iter().map(|d| format!("{d}\n")).collect::<String>()
        }
    };
    for d in domains.iter().chain(exclude).chain(server_domains) {
        if !valid_domain(d) {
            return Err(ZapretError::Domain(d.clone()));
        }
    }
    let excluded: Vec<String> = exclude.iter().chain(server_domains).cloned().collect();
    let ips: Vec<String> = server_ips
        .iter()
        .map(|ip| match ip {
            std::net::IpAddr::V4(v4) => format!("{v4}/32"),
            std::net::IpAddr::V6(v6) => format!("{v6}/128"),
        })
        .collect();
    Ok(UserLists {
        general: join(domains, EMPTY_HOSTLIST),
        exclude: join(&excluded, EMPTY_HOSTLIST),
        ipset_exclude: join(&ips, EMPTY_IPSET),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Сокращённый `general.bat` из релиза 1.10.4 — с тем же синтаксисом.
    const GENERAL: &str = r#"@echo off
chcp 65001 > nul
cd /d "%~dp0"
call service.bat status_zapret
set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
cd /d %BIN%

start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,2053,%GameFilterTCP% --wf-udp=443,19294-19344,%GameFilterUDP% ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --ip-id=zero --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_www_google_com.bin" --new ^
--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-fooling=ts --dpi-desync-fake-tls=^! --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new ^
--filter-tcp=%GameFilterTCP% --ipset="%LISTS%ipset-all.txt" --dpi-desync=multisplit --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n3
"#;

    #[test]
    fn parses_flowseal_bat() {
        let s = parse_bat("general", GENERAL).unwrap();
        assert_eq!(s.title, "Основная");
        assert!(s.recommended);
        assert!(s.needs_timestamps);
        assert_eq!(s.args[0], "--wf-tcp=80,443,2053,%GameFilterTCP%");
        assert!(s
            .args
            .contains(&"--hostlist=%LISTS%list-general.txt".to_string()));
        assert!(s.args.contains(&"--dpi-desync-fake-tls=!".to_string()));
        assert_eq!(s.args.iter().filter(|a| *a == "--new").count(), 3);
        assert_eq!(s.args.last().unwrap(), "--dpi-desync-cutoff=n3");
    }

    #[test]
    fn render_substitutes_only_our_directories() {
        let s = parse_bat("general (ALT4)", GENERAL).unwrap();
        assert_eq!(s.title, "ALT4");
        let args = render(
            &s,
            &RenderContext {
                bin: r"C:\Program Files\KVT\zapret\bin\",
                lists: r"C:\ProgramData\KVT\zapret\",
                game: GameFilter::Off,
                interface: Some(7),
            },
        );
        assert_eq!(args[0], "--wf-iface=7");
        assert_eq!(args[1], "--wf-tcp=80,443,2053,12");
        assert!(
            args.contains(&r"--hostlist=C:\ProgramData\KVT\zapret\list-general.txt".to_string())
        );
        assert!(args.iter().all(|a| !a.contains('%')));
        let all = render(
            &s,
            &RenderContext {
                bin: "b\\",
                lists: "l\\",
                game: GameFilter::All,
                interface: None,
            },
        );
        assert!(all[0].ends_with("1024-65535"));
    }

    /// Исключения KVT — в каждом профиле, даже где у Flowseal их нет.
    #[test]
    fn our_exclusions_reach_every_profile() {
        let s = parse_bat("general (ALT4)", GENERAL).unwrap();
        let args = render(
            &s,
            &RenderContext {
                bin: "b\\",
                lists: "l\\",
                game: GameFilter::Off,
                interface: Some(7),
            },
        );
        let profiles: Vec<&[String]> = args.split(|a| a == "--new").collect();
        assert_eq!(
            profiles.len(),
            s.args.iter().filter(|a| *a == "--new").count() + 1
        );
        for p in &profiles {
            let hostlist = p
                .iter()
                .filter(|a| *a == r"--hostlist-exclude=l\list-exclude-user.txt")
                .count();
            let ipset = p
                .iter()
                .filter(|a| *a == r"--ipset-exclude=l\ipset-exclude-user.txt")
                .count();
            let by_name = p.iter().any(|a| a.starts_with("--hostlist="));
            assert_eq!(ipset, 1, "{p:?}");
            // Профили без имени хоста (игровой фильтр по IP, catch-all) не должны
            // получить хостлист — иначе winws перестанет их выбирать.
            assert_eq!(hostlist, usize::from(by_name), "{p:?}");
        }
        assert!(profiles
            .iter()
            .any(|p| p.iter().any(|a| a.starts_with("--ipset="))
                && !p.iter().any(|a| a.starts_with("--hostlist"))));
        // Общие параметры остаются в начале, до первого профиля.
        assert!(args[0].starts_with("--wf-iface") && args[1].starts_with("--wf-tcp"));
    }

    #[test]
    fn dangerous_flags_and_paths_are_rejected() {
        let wrap = |args: &str| format!("start \"z\" /min \"%BIN%winws.exe\" {args}\n");
        for bad in [
            "--debug=@C:\\Windows\\System32\\evil.dll",
            "--hostlist=C:\\Users\\x\\list.txt",
            "--hostlist=%LISTS%..\\..\\secret.txt",
            "--hostlist=%BIN%sub\\file.txt",
            "--dpi-desync=fake & calc.exe",
            "--filter-tcp=443 --user=nobody",
            "--wf-tcp=80|calc",
            "--dpi-desync-repeats=%COMSPEC%",
            "--dpi-desync=fake --new --ip-id=\"zero\"x\"",
        ] {
            assert!(parse_bat("x", &wrap(bad)).is_err(), "{bad}");
        }
        assert_eq!(parse_bat("x", "echo hi"), Err(ZapretError::NoWinws));
        assert!(parse_bat("..\\evil", &wrap("--new")).is_err());
    }

    #[test]
    fn not_recommended_mark() {
        let text = format!(":: NOT RECOMMENDED\n{GENERAL}");
        assert!(!parse_bat("general (ALT5)", &text).unwrap().recommended);
    }

    #[test]
    fn sorting_follows_flowseal_menu() {
        let mk = |id: &str, recommended: bool| Strategy {
            id: id.into(),
            title: title(id),
            recommended,
            needs_timestamps: false,
            args: vec![],
        };
        let mut list = vec![
            mk("general (ALT5)", false),
            mk("general (SIMPLE FAKE)", true),
            mk("general (ALT10)", true),
            mk("general", true),
            mk("general (ALT2)", true),
        ];
        sort(&mut list);
        let ids: Vec<&str> = list.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "general",
                "general (ALT2)",
                "general (ALT10)",
                "general (SIMPLE FAKE)",
                "general (ALT5)"
            ]
        );
    }

    #[test]
    fn user_lists_keep_vpn_servers_out() {
        let lists = user_lists(
            &["youtube.com".into()],
            &["bank.ru".into()],
            &["vpn.example.com".into()],
            &[
                "203.0.113.10".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(lists.general, "youtube.com\n");
        assert_eq!(lists.exclude, "bank.ru\nvpn.example.com\n");
        assert_eq!(lists.ipset_exclude, "203.0.113.10/32\n2001:db8::1/128\n");
        let empty = user_lists(&[], &[], &[], &[]).unwrap();
        assert_eq!(empty.general, "domain.example.abc\n");
        assert_eq!(empty.ipset_exclude, "203.0.113.113/32\n");
        assert!(user_lists(&["evil.com\n--debug".into()], &[], &[], &[]).is_err());
        assert!(user_lists(&[], &["a b".into()], &[], &[]).is_err());
    }

    #[test]
    fn versions() {
        assert!(newer("1.10.4", "1.9.9"));
        assert!(newer("1.10.5", "1.10.4"));
        assert!(!newer("1.10.4", "1.10.4"));
        assert!(!newer("1.10", "1.10.4"));
        assert!(valid_version("1.10.4"));
        assert!(!valid_version("1.10.4; rm"));
        assert!(!valid_version("../1"));
    }

    #[test]
    fn known_binaries_only() {
        assert!(binary_known(
            "winws.exe",
            "AFFB4F69D2EA302A7ABCCD5325D81826E140DDAE014F1E070BC4A6C0DD555188"
        ));
        assert!(!binary_known("winws.exe", &"0".repeat(64)));
        assert!(!binary_known("cygwin1.dll", BINARY_HASHES[0].1));
        assert_eq!(BINARIES.len(), BINARY_HASHES.len());
    }

    #[test]
    fn release_from_github_api() {
        let json = br#"{"tag_name":"1.10.5","assets":[
            {"name":"zapret-discord-youtube-1.10.5.rar","browser_download_url":"https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.5/zapret-discord-youtube-1.10.5.rar","digest":"sha256:aa"},
            {"name":"zapret-discord-youtube-1.10.5.zip","browser_download_url":"https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.5/zapret-discord-youtube-1.10.5.zip","digest":"sha256:291AF673BD0238506F9548E0E94CA0ABF244000F4C9A06960544FB01C5F97B34"}]}"#;
        let r = parse_release(json).unwrap();
        assert_eq!(r.version, "1.10.5");
        assert_eq!(r.sha256, ARCHIVE_SHA256);
        assert!(r.zip_url.ends_with("1.10.5.zip"));
    }

    #[test]
    fn release_from_elsewhere_is_rejected() {
        let foreign = br#"{"tag_name":"1.10.5","assets":[{"name":"z.zip","browser_download_url":"https://evil.example/z.zip","digest":"sha256:291af673bd0238506f9548e0e94ca0abf244000f4c9a06960544fb01c5f97b34"}]}"#;
        assert!(parse_release(foreign).is_err());
        let no_digest = br#"{"tag_name":"1.10.5","assets":[{"name":"zapret-discord-youtube-1.10.5.zip","browser_download_url":"https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.5/zapret-discord-youtube-1.10.5.zip"}]}"#;
        assert!(parse_release(no_digest).is_err());
        let bad_tag = br#"{"tag_name":"../x","assets":[]}"#;
        assert!(parse_release(bad_tag).is_err());
    }

    #[test]
    fn domains() {
        assert!(valid_domain("rr1---sn-abc.googlevideo.com"));
        assert!(!valid_domain("a..b"));
        assert!(!valid_domain("x.com/path"));
        assert!(!valid_domain(""));
    }
}
