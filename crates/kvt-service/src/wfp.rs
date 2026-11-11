//! Kill switch на Windows Filtering Platform.
//!
//! Пока включён, исходящие соединения разрешены только:
//! - через интерфейс TUN;
//! - процессам ядра и службы (им нужно достучаться до VPN-сервера и до прямых адресов);
//! - на loopback, в локальную сеть и для DHCP.
//!
//! Всё остальное блокируется — в том числе если ядро упало и TUN исчез.
//!
//! Фильтры создаются в **динамической** сессии: Windows удаляет их сама, когда
//! закрывается handle движка — при выключении kill switch или при падении службы.
//! Поэтому сбой KVT не может оставить компьютер без интернета.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, GetBestInterface, GetIpAddrTable,
    GetIpForwardTable, MIB_IPADDRTABLE, MIB_IPFORWARDTABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, FWP_UINT64, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

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

const PERMIT_WEIGHT: u8 = 15;
const BLOCK_WEIGHT: u8 = 0;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn check(code: u32, what: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(kvt_core::trf!(
            "WFP {what}: код 0x{code:08X}",
            "WFP {what}: code 0x{code:08X}"
        )))
    }
}

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

/// Идентификатор приложения для условий WFP; память освобождается в Drop.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn for_path(path: &Path) -> io::Result<Self> {
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut blob: *mut FWP_BYTE_BLOB = null_mut();
        // SAFETY: путь завершён нулём; при успехе WFP выделяет blob, освобождаем в Drop.
        check(
            unsafe { FwpmGetAppIdFromFileName0(name.as_ptr(), &mut blob) },
            "app id",
        )?;
        Ok(AppId(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        // SAFETY: blob выделен FwpmGetAppIdFromFileName0 и освобождается один раз.
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}

pub struct KillSwitch {
    engine: HANDLE,
}

// SAFETY: handle движка WFP можно использовать из любого потока.
unsafe impl Send for KillSwitch {}
unsafe impl Sync for KillSwitch {}

impl KillSwitch {
    /// Включает kill switch. `apps` — процессы, которым разрешён выход в сеть
    /// мимо TUN; `tun_luid` — интерфейс туннеля. `kernel` — пропускать соединения,
    /// которые Windows приписывает ядру системы (нужно рядом с winws, см. `add_rules`).
    pub fn enable(apps: &[&Path], tun_luid: Option<u64>, kernel: bool) -> io::Result<Self> {
        let name = wide("KVT kill switch");
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                description: null_mut(),
            },
            ..Default::default()
        };
        let mut engine: HANDLE = null_mut();
        // SAFETY: локальный движок, стандартная аутентификация; session жива на время вызова.
        check(
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine) },
            kvt_core::i18n::tr("открытие движка", "opening the engine"),
        )?;
        // С этого момента Drop закроет движок, а вместе с ним и все добавленные фильтры.
        let ks = KillSwitch { engine };

        // SAFETY: движок открыт.
        check(
            unsafe { FwpmTransactionBegin0(ks.engine, 0) },
            kvt_core::i18n::tr("транзакция", "transaction"),
        )?;
        if let Err(e) = ks.add_rules(apps, tun_luid, kernel) {
            // SAFETY: транзакция начата выше.
            unsafe { FwpmTransactionAbort0(ks.engine) };
            return Err(e);
        }
        // SAFETY: транзакция начата выше.
        check(
            unsafe { FwpmTransactionCommit0(ks.engine) },
            kvt_core::i18n::tr("фиксация", "commit"),
        )?;
        Ok(ks)
    }

    fn add_rules(&self, apps: &[&Path], tun_luid: Option<u64>, kernel: bool) -> io::Result<()> {
        let sublayer = random_guid();
        let name = wide("KVT kill switch");
        let sub = FWPM_SUBLAYER0 {
            subLayerKey: sublayer,
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                description: null_mut(),
            },
            // Наш подслой проверяется раньше других.
            weight: u16::MAX,
            ..Default::default()
        };
        // SAFETY: структура и строка живы на время вызова.
        check(
            unsafe { FwpmSubLayerAdd0(self.engine, &sub, null_mut()) },
            kvt_core::i18n::tr("подслой", "sublayer"),
        )?;

        let app_ids = apps
            .iter()
            .map(|p| AppId::for_path(p))
            .collect::<io::Result<Vec<_>>>()?;

        for (layer, v6) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
        ] {
            let mut c = condition(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET);
            c.conditionValue.r#type = FWP_UINT32;
            c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
            self.add(layer, sublayer, &mut [c], FWP_ACTION_PERMIT, PERMIT_WEIGHT)?;

            // «Гибрид»: winws перехватывает пакеты на физическом интерфейсе и отправляет
            // их заново, а Windows проверяет такое соединение как соединение ядра
            // системы (приложение «System», pid 4) — не Xray и не службы. Журнал WFP
            // (2026-11-06): все отброшенные пакеты — «System», ALE_AUTH_CONNECT, наш
            // фильтр блокировки; к VPN-серверу, Telegram, Cloudflare. Без этого
            // разрешения kill switch глушил в «Гибриде» весь трафик мимо туннеля.
            // Цена: пока работает «Гибрид», соединения ядра Windows мимо туннеля тоже
            // не блокируются (обычные программы по-прежнему блокируются).
            if kernel {
                let mut system: Vec<u8> = "System\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                let mut blob = FWP_BYTE_BLOB {
                    size: system.len() as u32,
                    data: system.as_mut_ptr(),
                };
                let mut c = condition(FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL);
                c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                c.conditionValue.Anonymous.byteBlob = &mut blob;
                self.add(layer, sublayer, &mut [c], FWP_ACTION_PERMIT, PERMIT_WEIGHT)?;
            }

            for app in &app_ids {
                let mut c = condition(FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL);
                c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                c.conditionValue.Anonymous.byteBlob = app.0;
                self.add(layer, sublayer, &mut [c], FWP_ACTION_PERMIT, PERMIT_WEIGHT)?;
            }

            if let Some(luid) = tun_luid {
                let mut value = luid;
                let mut c = condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL);
                c.conditionValue.r#type = FWP_UINT64;
                c.conditionValue.Anonymous.uint64 = &mut value;
                self.add(layer, sublayer, &mut [c], FWP_ACTION_PERMIT, PERMIT_WEIGHT)?;
            }

            if v6 {
                for (addr, prefix) in LAN_V6 {
                    let mut mask = FWP_V6_ADDR_AND_MASK {
                        addr: addr.octets(),
                        prefixLength: *prefix,
                    };
                    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
                    c.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    c.conditionValue.Anonymous.v6AddrMask = &mut mask;
                    self.add(layer, sublayer, &mut [c], FWP_ACTION_PERMIT, PERMIT_WEIGHT)?;
                }
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
                    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
                    c.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    c.conditionValue.Anonymous.v4AddrMask = &mut mask;
                    self.add(layer, sublayer, &mut [c], FWP_ACTION_PERMIT, PERMIT_WEIGHT)?;
                }
            }

            // Всё остальное — блокировать.
            self.add(layer, sublayer, &mut [], FWP_ACTION_BLOCK, BLOCK_WEIGHT)?;
        }
        Ok(())
    }

    fn add(
        &self,
        layer: GUID,
        sublayer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: FWP_ACTION_TYPE,
        weight: u8,
    ) -> io::Result<()> {
        let name = wide("KVT kill switch");
        let mut filter = FWPM_FILTER0 {
            layerKey: layer,
            subLayerKey: sublayer,
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            ..Default::default()
        };
        filter.displayData.name = name.as_ptr().cast_mut();
        filter.action.r#type = action;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = weight;
        // SAFETY: фильтр, условия и все данные, на которые они указывают, живы
        // на время вызова; WFP копирует их внутрь.
        check(
            unsafe { FwpmFilterAdd0(self.engine, &filter, null_mut(), null_mut()) },
            kvt_core::i18n::tr("фильтр", "filter"),
        )
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        // SAFETY: движок открыт в enable и закрывается один раз. Динамическая
        // сессия при закрытии удаляет все свои фильтры.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

fn condition(field: GUID, match_type: i32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        ..Default::default()
    }
}

fn random_guid() -> GUID {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    GUID::from_u128(nanos ^ (u128::from(std::process::id()) << 96))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    fn loopback_interface_has_luid() {
        assert!(interface_luid("Loopback Pseudo-Interface 1").is_some());
        assert!(interface_luid("такого-интерфейса-нет").is_none());
    }

    /// Без прав администратора WFP отказывает — это должна быть понятная ошибка, а не падение.
    #[test]
    fn without_admin_rights_returns_error() {
        if crate::win::is_elevated() {
            return;
        }
        let err = KillSwitch::enable(&[], None, false)
            .err()
            .expect("без прав kill switch не включается");
        assert!(err.to_string().contains("WFP"), "{err}");
    }

    /// Только из терминала администратора:
    /// `cargo test -p kvt-service kill_switch -- --ignored`
    /// Пока kill switch включён, этот процесс (его нет в списке разрешённых) не может
    /// выйти в интернет; после выключения — может.
    #[test]
    #[ignore = "нужны права администратора"]
    fn kill_switch_blocks_and_releases() {
        let target = "1.1.1.1:443".parse().unwrap();
        let connect = || TcpStream::connect_timeout(&target, Duration::from_secs(3)).is_ok();
        assert!(connect(), "нет интернета — тест не имеет смысла");
        let ks = KillSwitch::enable(&[], None, false).expect("kill switch");
        assert!(!connect(), "kill switch пропустил соединение");
        drop(ks);
        assert!(connect(), "после выключения соединение должно работать");
    }
}
