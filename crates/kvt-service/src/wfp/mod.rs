//! Kill switch и защита DNS на Windows Filtering Platform.
//!
//! Kill switch, пока включён, разрешает соединения (исходящие и входящие) только:
//! - через интерфейс TUN;
//! - процессам ядра и службы, запущенным от учётной записи службы (им нужно
//!   достучаться до VPN-сервера и до прямых адресов); тестовому ядру окна — только к
//!   адресам проверяемых серверов (`KillSwitch::open_probe`);
//! - на loopback, с локальной сетью (кроме DNS) и для DHCP.
//!
//! Всё остальное блокируется — в том числе если ядро упало и TUN исчез.
//!
//! `DnsGuard` работает, пока подключён VPN, и без kill switch: DNS-запросы мимо
//! туннеля (Windows шлёт их во все интерфейсы сразу) блокируются, а если у TUN нет
//! IPv6 — и весь исходящий IPv6 мимо туннеля.
//!
//! Фильтры создаются в **динамической** сессии: Windows удаляет их сама, когда
//! закрывается handle движка — при выключении или при падении службы. Поэтому сбой
//! KVT не может оставить компьютер без интернета навсегда; после перезапуска служба
//! восстанавливает kill switch сама (`Supervisor::restore_kill_switch`).
//!
//! Состав: `engine` — сессия и фильтры, `conditions` — условия, `killswitch` и `dnsguard` —
//! наборы правил, `net` — интерфейсы и маршруты.

#![allow(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};
use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
};

/// Локальные сети и DHCP — доступны и при включённом kill switch.
const LAN_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];
const LAN_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];

/// Веса фильтров внутри подслоя: срабатывает подходящий фильтр с наибольшим.
const W_PERMIT: u8 = 15;
/// DNS мимо туннеля — блок даже в локальную сеть: запросы к DNS роутера видит провайдер.
const W_DNS: u8 = 10;
const W_LAN: u8 = 5;
/// «Гибрид»: ядру системы мимо туннеля закрыты порты общих папок (выше разрешения
/// ядра системы, но ниже локальной сети — свои общие папки в LAN работают).
const W_SYSTEM_BLOCK: u8 = 4;
const W_SYSTEM: u8 = 3;
const W_BLOCK: u8 = 0;

/// Порты RPC, NetBIOS и SMB. Клиент SMB работает в ядре Windows («System»): ссылка
/// `\\хост\папка` в письме или на странице открыла бы соединение мимо туннеля и
/// отдала бы реальный IP и NetNTLM-хэш.
const SMB_PORTS: [u16; 5] = [135, 137, 138, 139, 445];

/// DNS и DNS-over-TLS.
const DNS_PORTS: [u16; 2] = [53, 853];

/// Слои установления соединения: (слой, IPv6, входящее).
const LAYERS: [(GUID, bool, bool); 4] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false, false),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true, false),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false, true),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true, true),
];

mod conditions;
mod dnsguard;
mod engine;
mod killswitch;
mod net;
#[cfg(test)]
mod tests;

pub use dnsguard::DnsGuard;
pub use killswitch::KillSwitch;
pub use net::{best_interface, interface_index, interface_luid, physical_ipv4};
