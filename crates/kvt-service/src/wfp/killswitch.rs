//! Kill switch: разрешённый набор соединений, остальное закрыто (включая входящие).

use super::conditions::*;
use super::engine::{AppId, Filters};
use super::{
    LAN_V4, LAN_V6, LAYERS, SMB_PORTS, W_BLOCK, W_LAN, W_PERMIT, W_SYSTEM, W_SYSTEM_BLOCK,
};
use std::io;
use std::net::IpAddr;
use std::path::Path;
use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_V4_ADDR_AND_MASK, FWP_V6_ADDR_AND_MASK,
};

pub struct KillSwitch {
    filters: Filters,
    /// Адреса, открытые тестовому ядру (`open_probe`), и id их фильтров.
    probe: Vec<(IpAddr, [u64; 2])>,
}

impl KillSwitch {
    /// Включает kill switch. `apps` — процессы, которым разрешён выход в сеть
    /// мимо TUN (только от учётной записи службы); `tun_luid` — интерфейс туннеля
    /// (`None` — туннеля нет, открыта только локальная сеть). `kernel` — пропускать
    /// соединения, которые Windows приписывает ядру системы (нужно рядом с winws, см.
    /// `add_kill_switch_rules`).
    pub fn enable(apps: &[&Path], tun_luid: Option<u64>, kernel: bool) -> io::Result<Self> {
        let app_ids = AppId::for_paths(apps)?;
        let owner = crate::win::own_user_sd()?;
        let filters = Filters::install("KVT kill switch", |f| {
            for (layer, v6, inbound) in LAYERS {
                add_kill_switch_rules(f, layer, v6, inbound, &app_ids, &owner, tun_luid, kernel)?;
            }
            Ok(())
        })?;
        Ok(Self {
            filters,
            probe: Vec::new(),
        })
    }

    /// Полная проверка серверов из окна: тестовое ядро работает от пользователя, а
    /// kill switch пропускает ядра только от службы. Открывает `cores` (любой
    /// учётной записи) выход мимо туннеля — только к `ips`, в дополнение к уже
    /// открытым. Сколько всего адресов можно открыть, решает вызывающий.
    pub fn open_probe(&mut self, cores: &[&Path], ips: &[IpAddr]) -> io::Result<()> {
        let app_ids = AppId::for_paths(cores)?;
        let mut fresh: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| !self.probe.iter().any(|(open, _)| open == ip))
            .collect();
        fresh.sort_unstable();
        fresh.dedup();
        let filters = &self.filters;
        let added = filters.transaction(|| {
            fresh
                .iter()
                .map(|ip| Ok((*ip, permit_probe(filters, &app_ids, *ip)?)))
                .collect::<io::Result<Vec<_>>>()
        })?;
        self.probe.extend(added);
        Ok(())
    }

    /// Сколько адресов сейчас открыто тестовому ядру.
    pub fn probe_len(&self) -> usize {
        self.probe.len()
    }

    /// Сколько из `ips` ещё не открыто (без повторов).
    pub fn probe_fresh(&self, ips: &[IpAddr]) -> usize {
        let mut fresh: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| !self.probe.iter().any(|(open, _)| open == ip))
            .collect();
        fresh.sort_unstable();
        fresh.dedup();
        fresh.len()
    }

    /// Закрывает `count` самых давно открытых адресов: их серверы уже проверены —
    /// одновременно проверяется лишь несколько серверов.
    pub fn close_oldest_probe(&mut self, count: usize) {
        let count = count.min(self.probe.len());
        for (_, ids) in self.probe.drain(..count) {
            for id in ids {
                self.filters.delete(id);
            }
        }
    }

    /// Закрывает всё, что открыл `open_probe`.
    pub fn close_probe(&mut self) {
        for (_, ids) in self.probe.drain(..) {
            for id in ids {
                self.filters.delete(id);
            }
        }
    }
}

/// Разрешение тестовому ядру к одному адресу: исходящее и входящее (UDP Hysteria2).
/// Условия с одним полем WFP объединяет через «или»: любое из ядер.
fn permit_probe(f: &Filters, cores: &[AppId], ip: IpAddr) -> io::Result<[u64; 2]> {
    let (connect, accept) = match ip {
        IpAddr::V4(_) => (
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        ),
        IpAddr::V6(_) => (
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ),
    };
    let mut v4 = FWP_V4_ADDR_AND_MASK {
        addr: 0,
        mask: u32::MAX,
    };
    let mut v6 = FWP_V6_ADDR_AND_MASK {
        addr: [0; 16],
        prefixLength: 128,
    };
    match ip {
        IpAddr::V4(addr) => v4.addr = u32::from(addr),
        IpAddr::V6(addr) => v6.addr = addr.octets(),
    }
    let mut ids = [0u64; 2];
    for (slot, layer) in ids.iter_mut().zip([connect, accept]) {
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> =
            cores.iter().map(|core| app_is(core.0)).collect();
        conditions.push(match ip {
            IpAddr::V4(_) => remote_v4(&mut v4),
            IpAddr::V6(_) => remote_v6(&mut v6),
        });
        *slot = f.add_id(layer, &mut conditions, FWP_ACTION_PERMIT, W_PERMIT)?;
    }
    Ok(ids)
}

/// Правила kill switch на одном слое. Входящие соединения закрыты так же, как
/// исходящие: иначе торрент-клиент, RDP или общие папки принимали бы соединения
/// на внешний адрес мимо туннеля.
#[allow(clippy::too_many_arguments)]
fn add_kill_switch_rules(
    f: &Filters,
    layer: GUID,
    v6: bool,
    inbound: bool,
    apps: &[AppId],
    owner: &[u8],
    tun_luid: Option<u64>,
    kernel: bool,
) -> io::Result<()> {
    f.permit_trusted(layer, apps, owner, tun_luid)?;

    // «Гибрид»: winws перехватывает пакеты на физическом интерфейсе и отправляет
    // их заново, а Windows проверяет такое соединение как соединение ядра
    // системы (приложение «System», pid 4) — не Xray и не службы. Журнал WFP
    // (2026-11-06): все отброшенные пакеты — «System», ALE_AUTH_CONNECT, наш
    // фильтр блокировки; к VPN-серверу, Telegram, Cloudflare. Без этого
    // разрешения kill switch глушил в «Гибриде» весь трафик мимо туннеля.
    // Цена: пока работает «Гибрид», исходящие соединения ядра Windows мимо туннеля
    // тоже не блокируются (обычные программы по-прежнему блокируются), кроме портов
    // общих папок (`SMB_PORTS`). Разрешение ниже блокировки DNS и локальной сети,
    // поэтому DNS ядру системы мимо туннеля закрыт, а LAN открыта, как всем. Входящие —
    // нет: от имени «System» их принимают общие папки (SMB) и HTTP.sys, а ответы
    // на соединения, которые отправил winws, этот слой не проходят.
    if kernel && !inbound {
        let mut system: Vec<u8> = "System\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut blob = FWP_BYTE_BLOB {
            size: system.len() as u32,
            data: system.as_mut_ptr(),
        };
        for port in SMB_PORTS {
            f.add(
                layer,
                &mut [app_is(&mut blob), remote_port(port)],
                FWP_ACTION_BLOCK,
                W_SYSTEM_BLOCK,
            )?;
        }
        f.permit(layer, &mut [app_is(&mut blob)], W_SYSTEM)?;
    }

    if !inbound {
        f.block_dns(layer)?;
    }

    if v6 {
        permit_lan_v6(f, layer)?;
    } else {
        for (addr, prefix) in LAN_V4 {
            let mut mask = FWP_V4_ADDR_AND_MASK {
                addr: u32::from(*addr),
                mask: if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                },
            };
            f.permit(layer, &mut [remote_v4(&mut mask)], W_LAN)?;
        }
    }

    // DHCP: продление аренды идёт на адрес сервера DHCP, а он бывает и не из
    // локальной сети (кабель провайдера напрямую). Только UDP между портами
    // клиента и сервера — в обе стороны компьютер остаётся клиентом.
    let (client, server) = if v6 { (546, 547) } else { (68, 67) };
    f.permit(
        layer,
        &mut [udp(), local_port(client), remote_port(server)],
        W_LAN,
    )?;

    // Всё остальное — блокировать.
    f.add(layer, &mut [], FWP_ACTION_BLOCK, W_BLOCK)
}

/// Link-local и multicast IPv6 (соседи, DHCPv6, обнаружение в LAN).
pub(super) fn permit_lan_v6(f: &Filters, layer: GUID) -> io::Result<()> {
    for (addr, prefix) in LAN_V6 {
        let mut mask = FWP_V6_ADDR_AND_MASK {
            addr: addr.octets(),
            prefixLength: *prefix,
        };
        f.permit(layer, &mut [remote_v6(&mut mask)], W_LAN)?;
    }
    Ok(())
}
