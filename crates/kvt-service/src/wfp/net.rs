//! Интерфейсы и маршруты Windows (IP Helper): LUID и индекс по имени, лучший интерфейс
//! к адресу, физический адрес. WFP здесь нет.

use super::engine::wide;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, GetBestInterface, GetIpAddrTable,
    GetIpForwardTable, MIB_IPADDRTABLE, MIB_IPFORWARDTABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

/// LUID сетевого интерфейса по его имени (например, «KVT» — интерфейс TUN).
pub fn interface_luid(alias: &str) -> Option<u64> {
    let name = wide(alias);
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: имя завершено нулём, luid — валидный указатель.
    let rc = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
    if rc != 0 {
        return None;
    }
    // SAFETY: функция заполнила union целиком; Value — его 64-битное представление.
    Some(unsafe { luid.Value })
}

/// Индекс интерфейса по имени (`None` — такого интерфейса нет).
pub fn interface_index(alias: &str) -> Option<u32> {
    let luid = NET_LUID_LH {
        Value: interface_luid(alias)?,
    };
    let mut index = 0u32;
    // SAFETY: luid заполнен, index — валидный указатель.
    (unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } == 0).then_some(index)
}

/// Интерфейс, через который система отправит пакет к `dest`.
pub fn best_interface(dest: Ipv4Addr) -> Option<u32> {
    let mut index = 0u32;
    // Адрес — в сетевом порядке байт, как его хранит IN_ADDR.
    let addr = u32::from_ne_bytes(dest.octets());
    // SAFETY: index — валидный указатель.
    (unsafe { GetBestInterface(addr, &mut index) } == 0).then_some(index)
}

/// IPv4-адрес физического адаптера, через который идёт маршрут по умолчанию в
/// обход TUN. Сокет, привязанный к этому адресу, уходит напрямую в сеть
/// провайдера, даже когда VPN подключён (в Windows маршрут выбирается с учётом
/// адреса источника).
pub fn physical_ipv4() -> Option<Ipv4Addr> {
    let tun = interface_index(kvt_core::compile::TUN_INTERFACE);
    let index = default_routes()
        .into_iter()
        .filter(|(index, _)| Some(*index) != tun)
        .min_by_key(|(_, metric)| *metric)?
        .0;
    interface_addresses()
        .into_iter()
        .find(|(i, addr)| *i == index && !addr.is_unspecified() && !addr.is_link_local())
        .map(|(_, addr)| addr)
}

/// Маршруты 0.0.0.0/0: (индекс интерфейса, метрика).
fn default_routes() -> Vec<(u32, u32)> {
    let mut size = 0u32;
    // SAFETY: первый вызов с пустым буфером только сообщает нужный размер.
    unsafe { GetIpForwardTable(null_mut(), &mut size, 0) };
    if size == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let table = buf.as_mut_ptr().cast::<MIB_IPFORWARDTABLE>();
    // SAFETY: буфер выровнен по 8 байт и имеет запрошенный размер.
    if unsafe { GetIpForwardTable(table, &mut size, 0) } != 0 {
        return Vec::new();
    }
    // SAFETY: функция заполнила dwNumEntries строк подряд внутри буфера.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize)
    };
    rows.iter()
        .filter(|r| r.dwForwardDest == 0 && r.dwForwardMask == 0)
        .map(|r| (r.dwForwardIfIndex, r.dwForwardMetric1))
        .collect()
}

/// IPv4-адреса интерфейсов: (индекс интерфейса, адрес).
fn interface_addresses() -> Vec<(u32, Ipv4Addr)> {
    let mut size = 0u32;
    // SAFETY: первый вызов с пустым буфером только сообщает нужный размер.
    unsafe { GetIpAddrTable(null_mut(), &mut size, 0) };
    if size == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let table = buf.as_mut_ptr().cast::<MIB_IPADDRTABLE>();
    // SAFETY: буфер выровнен по 8 байт и имеет запрошенный размер.
    if unsafe { GetIpAddrTable(table, &mut size, 0) } != 0 {
        return Vec::new();
    }
    // SAFETY: функция заполнила dwNumEntries строк подряд внутри буфера.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize)
    };
    rows.iter()
        // Адрес — в сетевом порядке байт.
        .map(|r| (r.dwIndex, Ipv4Addr::from(r.dwAddr.to_ne_bytes())))
        .collect()
}
