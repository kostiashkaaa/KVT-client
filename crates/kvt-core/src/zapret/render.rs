//! Аргументы winws для запуска: подстановка каталогов, игрового фильтра и списков в
//! шаблон стратегии. Каталоги подставляет служба — свои.

use super::bat::{BIN, GAME_TCP, GAME_UDP, LISTS};
use super::Strategy;
use serde::{Deserialize, Serialize};

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
