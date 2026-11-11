//! Текущая сеть: адаптер, через который система выходит в интернет, его шлюз и
//! DNS-серверы. Сеть узнаётся по MAC-адресу шлюза: он один и тот же у домашнего
//! роутера, а у телефона в режиме модема — свой. Имя Wi-Fi Windows 11 отдаёт
//! только с разрешением на геолокацию, поэтому оно необязательно.

#![allow(unsafe_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt as _;
use std::ptr::null_mut;
use std::sync::Mutex;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIpForwardTable2, GetIpNetTable2,
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL,
    IF_TYPE_WWANPP, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_TABLE2, MIB_IPNET_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN, SOCKET_ADDRESS};

const ERROR_BUFFER_OVERFLOW: u32 = 111;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const IF_TYPE_WWANPP2: u32 = 244;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetKind {
    Wifi,
    Ethernet,
    Mobile,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    /// Отпечаток сети (хэш, без MAC-адреса в открытом виде).
    pub key: String,
    /// Имя Wi-Fi, если Windows его отдаёт, иначе имя адаптера.
    pub label: String,
    pub kind: NetKind,
    #[serde(skip)]
    pub dns: Vec<Ipv4Addr>,
}

/// Сырые сведения об адаптере — отдельно от WinAPI, чтобы выбор был тестируемым.
#[derive(Debug, Clone)]
struct Adapter {
    guid: String,
    name: String,
    description: String,
    if_type: u32,
    up: bool,
    metric: u32,
    /// Метрика маршрута по умолчанию через этот адаптер; `None` — маршрута нет.
    route_metric: Option<u32>,
    luid: u64,
    gateway: Option<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
    /// Свой IPv4-адрес адаптера (не 169.254.x.x).
    address: Option<Ipv4Addr>,
}

fn kind(if_type: u32) -> NetKind {
    match if_type {
        IF_TYPE_IEEE80211 => NetKind::Wifi,
        IF_TYPE_ETHERNET_CSMACD => NetKind::Ethernet,
        IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => NetKind::Mobile,
        _ => NetKind::Other,
    }
}

/// Адаптер, через который Windows отправит трафик в интернет: маршрут по умолчанию
/// с наименьшей итоговой метрикой (маршрут + интерфейс, как считает сама Windows).
/// TUN KVT и чужие туннели (wintun других VPN-клиентов) сетью не считаются.
fn pick(adapters: &[Adapter]) -> Option<&Adapter> {
    adapters
        .iter()
        .filter(|a| a.up && a.gateway.is_some())
        .filter(|a| !matches!(a.if_type, IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_TUNNEL))
        .filter(|a| a.name != kvt_core::compile::TUN_INTERFACE)
        .filter(|a| !a.description.to_ascii_lowercase().contains("wintun"))
        .filter_map(|a| Some((a.route_metric?.saturating_add(a.metric), a)))
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, a)| a)
}

/// Маршруты по умолчанию IPv4: LUID интерфейса → наименьшая метрика маршрута.
fn default_routes() -> Vec<(u64, u32)> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    let mut out: Vec<(u64, u32)> = Vec::new();
    // SAFETY: GetIpForwardTable2 выделяет таблицу сам; освобождаем через FreeMibTable.
    unsafe {
        if GetIpForwardTable2(AF_INET, &mut table) != 0 || table.is_null() {
            return out;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows
            .iter()
            .filter(|r| r.DestinationPrefix.PrefixLength == 0)
        {
            let luid = row.InterfaceLuid.Value;
            match out.iter_mut().find(|(l, _)| *l == luid) {
                Some((_, m)) => *m = (*m).min(row.Metric),
                None => out.push((luid, row.Metric)),
            }
        }
        FreeMibTable(table.cast());
    }
    out
}

fn fingerprint(
    kind: NetKind,
    gateway: Ipv4Addr,
    gateway_mac: Option<[u8; 6]>,
    guid: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(b"kvt-network-v1");
    h.update(format!("{kind:?}").as_bytes());
    match gateway_mac {
        // Один и тот же роутер — одна сеть, даже через другой адаптер.
        Some(mac) => h.update(mac),
        None => {
            h.update(gateway.octets());
            h.update(guid.as_bytes());
        }
    }
    h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: строки из GetAdaptersAddresses оканчиваются нулём и живут, пока жив буфер.
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn ipv4(addr: &SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    if addr.lpSockaddr.is_null() {
        return None;
    }
    // SAFETY: lpSockaddr указывает на SOCKADDR длиной iSockaddrLength; семейство
    // проверяется до приведения к SOCKADDR_IN.
    unsafe {
        if (*addr.lpSockaddr).sa_family != AF_INET
            || (addr.iSockaddrLength as usize) < std::mem::size_of::<SOCKADDR_IN>()
        {
            return None;
        }
        let sin = &*(addr.lpSockaddr as *const SOCKADDR_IN);
        Some(Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes()))
    }
}

fn adapters() -> Vec<Adapter> {
    let routes = default_routes();
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: буфер выровнен по 8 байт и имеет размер `size`.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match rc {
            0 => break,
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return Vec::new(),
        }
    }

    let mut out = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: обход связного списка, который заполнил GetAdaptersAddresses в `buf`.
    unsafe {
        while !cur.is_null() {
            let a = &*cur;
            let mut gateway = None;
            let mut g = a.FirstGatewayAddress;
            while !g.is_null() && gateway.is_none() {
                gateway = ipv4(&(*g).Address);
                g = (*g).Next;
            }
            let mut address = None;
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() && address.is_none() {
                address = ipv4(&(*u).Address).filter(|ip| !ip.is_link_local());
                u = (*u).Next;
            }
            let mut dns = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                dns.extend(ipv4(&(*d).Address));
                d = (*d).Next;
            }
            let guid = if a.AdapterName.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(a.AdapterName.cast())
                    .to_string_lossy()
                    .into_owned()
            };
            let luid = a.Luid.Value;
            out.push(Adapter {
                guid,
                name: wide(a.FriendlyName),
                description: wide(a.Description),
                if_type: a.IfType,
                up: a.OperStatus == IfOperStatusUp,
                metric: a.Ipv4Metric,
                route_metric: routes.iter().find(|(l, _)| *l == luid).map(|(_, m)| *m),
                luid,
                gateway,
                dns,
                address,
            });
            cur = a.Next;
        }
    }
    out
}

/// MAC-адрес шлюза из таблицы соседей (ARP). Пакетов не отправляет.
fn gateway_mac(luid: u64, gateway: Ipv4Addr) -> Option<[u8; 6]> {
    let mut table: *mut MIB_IPNET_TABLE2 = null_mut();
    // SAFETY: GetIpNetTable2 выделяет таблицу сам; освобождаем через FreeMibTable.
    unsafe {
        if GetIpNetTable2(AF_INET, &mut table) != 0 || table.is_null() {
            return None;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let found = rows.iter().find_map(|row| {
            let ip = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            let mac = &row.PhysicalAddress[..row.PhysicalAddressLength.min(32) as usize];
            (row.InterfaceLuid.Value == luid
                && row.Address.si_family == AF_INET
                && ip == gateway
                && mac.len() == 6
                && mac.iter().any(|b| *b != 0))
            .then(|| {
                let mut m = [0u8; 6];
                m.copy_from_slice(mac);
                m
            })
        });
        FreeMibTable(table.cast());
        found
    }
}

/// Имя Wi-Fi из `netsh wlan show interfaces`. Без разрешения на геолокацию
/// Windows 11 его не отдаёт — тогда `None`.
fn wifi_name() -> Option<String> {
    let out = std::process::Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    parse_ssid(&String::from_utf8_lossy(&out.stdout))
}

fn parse_ssid(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let value = value.trim();
        (key.trim() == "SSID" && !value.is_empty()).then(|| value.to_owned())
    })
}

/// Адрес физического адаптера, через который идёт интернет (мимо TUN KVT). Сокет,
/// привязанный к нему, уходит мимо туннеля — так проверка серверов работает и при
/// подключённом VPN. Без сетевых запросов.
pub fn physical_ipv4() -> Option<Ipv4Addr> {
    pick(&adapters())?.address
}

/// Сеть, через которую сейчас идёт трафик. `None` — сети нет.
pub fn current() -> Option<Network> {
    current_with(false)
}

/// То же, но с именем Wi-Fi (запускает netsh — только при смене сети).
pub fn current_named() -> Option<Network> {
    current_with(true)
}

/// MAC шлюза, который видели последним, — по адаптеру и адресу шлюза.
type MacKey = (String, Ipv4Addr);
static KNOWN_MACS: Mutex<Option<HashMap<MacKey, [u8; 6]>>> = Mutex::new(None);

/// MAC шлюза с памятью. Пока весь трафик идёт в туннель, компьютер почти не говорит
/// с роутером напрямую, и его запись в таблице ARP устаревает и пропадает. Без памяти
/// отпечаток сети в этот момент менялся бы (MAC → адрес шлюза), а когда запись
/// возвращалась — менялся обратно. Профили сетей принимали каждое такое мигание за
/// смену сети, и в «Гибриде» KVT переподключался раз в пару минут. Новый MAC при
/// том же шлюзе (другой роутер) по-прежнему меняет отпечаток.
fn stable_mac(
    known: &mut HashMap<MacKey, [u8; 6]>,
    guid: &str,
    gateway: Ipv4Addr,
    seen: Option<[u8; 6]>,
) -> Option<[u8; 6]> {
    let key = (guid.to_owned(), gateway);
    match seen {
        Some(mac) => {
            known.insert(key, mac);
            Some(mac)
        }
        None => known.get(&key).copied(),
    }
}

fn current_with(named: bool) -> Option<Network> {
    let all = adapters();
    let a = pick(&all)?;
    let gateway = a.gateway?;
    let kind = kind(a.if_type);
    let label = (named && kind == NetKind::Wifi)
        .then(wifi_name)
        .flatten()
        .unwrap_or_else(|| a.name.clone());
    let seen = gateway_mac(a.luid, gateway);
    let mac = {
        let mut guard = KNOWN_MACS.lock().unwrap_or_else(|e| e.into_inner());
        stable_mac(
            guard.get_or_insert_with(HashMap::new),
            &a.guid,
            gateway,
            seen,
        )
    };
    Some(Network {
        key: fingerprint(kind, gateway, mac, &a.guid),
        label,
        kind,
        dns: a.dns.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(name: &str, if_type: u32, metric: u32, gateway: bool) -> Adapter {
        Adapter {
            guid: format!("{{{name}}}"),
            name: name.into(),
            description: String::new(),
            if_type,
            up: true,
            metric,
            route_metric: gateway.then_some(0),
            luid: 1,
            gateway: gateway.then_some(Ipv4Addr::new(192, 168, 1, 1)),
            dns: vec![],
            address: gateway.then_some(Ipv4Addr::new(192, 168, 1, 10)),
        }
    }

    #[test]
    fn network_key_survives_arp_entry_expiring() {
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        let router = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let mut known = HashMap::new();
        let key = |known: &mut HashMap<MacKey, [u8; 6]>, seen| {
            let mac = stable_mac(known, "{eth}", gw, seen);
            fingerprint(NetKind::Ethernet, gw, mac, "{eth}")
        };
        let with_mac = key(&mut known, Some(router));
        // Туннель поднят, запись ARP пропала — сеть та же.
        assert_eq!(key(&mut known, None), with_mac);
        assert_eq!(key(&mut known, Some(router)), with_mac);
        // Другой роутер с тем же адресом — другая сеть.
        assert_ne!(key(&mut known, Some([1, 2, 3, 4, 5, 6])), with_mac);
        // Шлюз ни разу не видели — как раньше, по адресу и адаптеру.
        assert_eq!(
            stable_mac(&mut known, "{wifi}", Ipv4Addr::new(10, 0, 0, 1), None),
            None
        );
    }

    #[test]
    fn picks_physical_adapter_with_lowest_metric() {
        let mut other_vpn = adapter("Happ", IF_TYPE_ETHERNET_CSMACD, 1, true);
        other_vpn.description = "WireGuard Wintun Userspace Tunnel".into();
        let adapters = [
            adapter("KVT", IF_TYPE_ETHERNET_CSMACD, 0, true),
            other_vpn,
            adapter("Ethernet", IF_TYPE_ETHERNET_CSMACD, 25, true),
            adapter("Беспроводная сеть", IF_TYPE_IEEE80211, 35, true),
            adapter("Bluetooth", IF_TYPE_ETHERNET_CSMACD, 5, false),
        ];
        assert_eq!(pick(&adapters).unwrap().name, "Ethernet");
    }

    /// Как на этом компьютере: у Radmin VPN метрика интерфейса 1, но маршрут
    /// по умолчанию с метрикой 9256 — интернет идёт через Ethernet.
    #[test]
    fn effective_metric_decides() {
        let mut radmin = adapter("Radmin VPN", IF_TYPE_ETHERNET_CSMACD, 1, true);
        radmin.route_metric = Some(9256);
        let mut lan = adapter("VirtualBox", IF_TYPE_ETHERNET_CSMACD, 1, true);
        lan.route_metric = None;
        let adapters = [
            radmin,
            lan,
            adapter("Ethernet", IF_TYPE_ETHERNET_CSMACD, 25, true),
        ];
        assert_eq!(pick(&adapters).unwrap().name, "Ethernet");
    }

    #[test]
    fn same_router_same_key() {
        let mac = Some([0xAA, 0xBB, 0xCC, 0, 1, 2]);
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            fingerprint(NetKind::Wifi, gw, mac, "{a}"),
            fingerprint(NetKind::Wifi, gw, mac, "{b}")
        );
        assert_ne!(
            fingerprint(NetKind::Wifi, gw, mac, "{a}"),
            fingerprint(NetKind::Wifi, gw, Some([0xAA, 0xBB, 0xCC, 0, 1, 3]), "{a}")
        );
        // Без MAC (модем, PPP) различаем по шлюзу и адаптеру.
        assert_ne!(
            fingerprint(NetKind::Mobile, gw, None, "{a}"),
            fingerprint(NetKind::Mobile, gw, None, "{b}")
        );
        assert_eq!(fingerprint(NetKind::Wifi, gw, mac, "{a}").len(), 16);
    }

    #[test]
    fn ssid_parsing() {
        let text = "\
    Имя                    : Беспроводная сеть
    SSID                   : Home 5G
    BSSID                  : aa:bb:cc:dd:ee:ff";
        assert_eq!(parse_ssid(text).as_deref(), Some("Home 5G"));
        assert_eq!(
            parse_ssid("Network shell commands need location permission"),
            None
        );
    }

    /// `cargo test -p kvt-app real_network -- --ignored --nocapture`
    #[test]
    #[ignore = "читает сетевые адаптеры этого компьютера"]
    fn real_network() {
        println!("{:?}", current_named());
    }
}
