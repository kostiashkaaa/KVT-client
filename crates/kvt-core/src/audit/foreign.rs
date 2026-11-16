//! Что считать чужим: каталоги KVT, другие VPN-клиенты с их ядрами и адаптерами,
//! признаки чужого zapret. Решает по тексту фактов, к системе не обращается.

use super::{Adapter, Autostart, Facts, Service};

/// Другие VPN-клиенты: имя процесса (без `.exe`, в нижнем регистре) → название.
pub(super) const VPN_CLIENTS: &[(&str, &str)] = &[
    ("v2rayn", "v2rayN"),
    ("nekoray", "NekoRay"),
    ("nekobox", "NekoBox"),
    ("throne", "Throne"),
    ("hiddify", "Hiddify"),
    ("hiddifycli", "Hiddify"),
    ("happ", "Happ"),
    ("clash-verge", "Clash Verge"),
    ("verge-mihomo", "Clash Verge"),
    ("flclash", "FlClash"),
    ("clash for windows", "Clash for Windows"),
    ("amneziavpn", "AmneziaVPN"),
    ("amneziawg", "AmneziaWG"),
    ("wireguard", "WireGuard"),
    ("openvpn", "OpenVPN"),
    ("openvpn-gui", "OpenVPN"),
    ("outline", "Outline"),
    ("protonvpn", "Proton VPN"),
    ("protonvpn.client", "Proton VPN"),
    ("nordvpn", "NordVPN"),
    ("windscribe", "Windscribe"),
    ("psiphon3", "Psiphon"),
    ("lantern", "Lantern"),
    ("adguardvpn", "AdGuard VPN"),
    ("zapretkvn", "Zapret KVN"),
    ("zapretvpn", "ZapretVPN"),
    ("antizapret", "AntiZapret"),
];

/// Ядра, которые запускают другие клиенты. Считаются чужими, только если путь
/// известен и лежит не в каталоге KVT (свои ядра запускает служба).
pub(super) const CORES: &[&str] = &["xray", "sing-box", "mihomo", "clash", "tun2socks"];

/// Признаки виртуальных адаптеров других VPN (в описании адаптера).
const TUNNEL_ADAPTERS: &[&str] = &[
    "tap-windows",
    "tap-protonvpn",
    "tap-nordvpn",
    "wintun",
    "wireguard",
    "amneziawg",
    "openvpn",
    "outline",
    "hiddify",
    "mihomo",
    "clash",
    "meta tunnel",
    "sing-tun",
];

/// Признаки zapret в командах автозагрузки и службах.
const ZAPRET_MARKERS: &[&str] = &["winws", "goodbyedpi", "zapret", "discordfix"];

fn has_marker(text: &str) -> bool {
    let t = text.to_lowercase();
    ZAPRET_MARKERS.iter().any(|m| t.contains(m))
}

/// Каталоги KVT в нижнем регистре и с `\\` на конце (см. [`own_dirs`]).
pub struct OwnDirs(Vec<String>);

/// Каталоги, файлы из которых принадлежат KVT: каталог программы и
/// `ProgramData\\KVT` (обновлённый комплект zapret).
pub fn own_dirs<S: AsRef<str>>(dirs: &[S]) -> OwnDirs {
    OwnDirs(
        dirs.iter()
            .map(|d| normalize_dir(d.as_ref()))
            .filter(|d| !d.is_empty())
            .collect(),
    )
}

/// Путь (или командная строка) указывает внутрь каталога KVT.
pub(super) fn is_own(path: &str, own: &OwnDirs) -> bool {
    let p = path.to_lowercase().replace('/', "\\");
    own.0.iter().any(|d| p.contains(d.as_str()))
}

/// Служба zapret другой сборки (не KVT).
pub fn is_foreign_zapret_service(s: &Service, own: &OwnDirs) -> bool {
    has_marker(&format!("{} {} {}", s.name, s.display_name, s.path)) && !is_own(&s.path, own)
}

/// Запись автозагрузки, которая запускает чужой zapret и ещё не отключена.
pub fn is_zapret_autostart(a: &Autostart, own: &OwnDirs) -> bool {
    !a.disabled && has_marker(&format!("{} {}", a.name, a.command)) && !is_own(&a.command, own)
}

/// Процесс другого VPN-клиента или его ядра — только такой можно закрыть по кнопке.
pub fn is_vpn_process_name(image: &str) -> bool {
    let name = image.trim().to_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    VPN_CLIENTS.iter().any(|(n, _)| *n == name) || CORES.contains(&name)
}

pub fn normalize_dir(dir: &str) -> String {
    let d = dir.trim().to_lowercase().replace('/', "\\");
    if d.is_empty() || d.ends_with('\\') {
        d
    } else {
        d + "\\"
    }
}

pub(super) fn is_tunnel_adapter(a: &Adapter) -> bool {
    let d = a.description.to_lowercase();
    TUNNEL_ADAPTERS.iter().any(|m| d.contains(m))
}

/// Адаптер KVT (имя задаёт `compile::TUN_INTERFACE`).
pub(super) fn is_own_adapter(a: &Adapter) -> bool {
    a.name.eq_ignore_ascii_case(crate::compile::TUN_INTERFACE)
}

/// Найти в свежем сборе фактов запись автозагрузки zapret по идентификатору.
pub fn zapret_autostart_by_id<'a>(
    facts: &'a Facts,
    id: &str,
    own: &OwnDirs,
) -> Option<&'a Autostart> {
    facts
        .autostart
        .iter()
        .find(|a| a.id() == id && is_zapret_autostart(a, own))
}
