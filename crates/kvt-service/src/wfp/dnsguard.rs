//! Защита DNS: порты 53 и 853 мимо туннеля закрыты, пока подключён VPN; без туннельного
//! IPv6 закрыт и весь исходящий IPv6 мимо туннеля.

use super::engine::{AppId, Filters};
use super::killswitch::permit_lan_v6;
use super::{LAYERS, W_BLOCK};
use std::io;
use std::path::Path;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_BLOCK;

/// DNS только через туннель, пока работает VPN: и без kill switch.
///
/// Windows отправляет DNS-запросы во все интерфейсы сразу и берёт первый ответ — в
/// том числе DNS роутера или провайдера на физическом адаптере. У sing-box от этого
/// спасает `strict_route`, у Xray аналога нет. Пропускаются туннель, loopback и
/// процессы ядра и службы (ядро само ходит к локальному резолверу за прямыми
/// доменами и именем сервера); остальное на порты 53 и 853 блокируется.
///
/// `block_ipv6` — у TUN нет IPv6 (выключен у адаптера или Windows не дала его
/// настроить): маршрут `::/0` остаётся у физического адаптера, и программы со своим
/// DoH или с IPv6-адресом ушли бы мимо туннеля с реальным адресом. Тогда исходящий
/// IPv6 закрыт целиком, кроме link-local и multicast; программы откатываются на IPv4,
/// который идёт через туннель.
pub struct DnsGuard {
    _filters: Filters,
}

impl DnsGuard {
    pub fn enable(apps: &[&Path], tun_luid: u64, block_ipv6: bool) -> io::Result<Self> {
        let app_ids = AppId::for_paths(apps)?;
        let owner = crate::win::own_user_sd()?;
        let filters = Filters::install("KVT DNS", |f| {
            for (layer, v6, inbound) in LAYERS {
                if inbound {
                    continue;
                }
                f.permit_trusted(layer, &app_ids, &owner, Some(tun_luid))?;
                f.block_dns(layer)?;
                if v6 && block_ipv6 {
                    permit_lan_v6(f, layer)?;
                    f.add(layer, &mut [], FWP_ACTION_BLOCK, W_BLOCK)?;
                }
            }
            Ok(())
        })?;
        Ok(Self { _filters: filters })
    }
}
