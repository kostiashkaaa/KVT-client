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

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
};
use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;
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

    fn for_paths(paths: &[&Path]) -> io::Result<Vec<Self>> {
        paths.iter().map(|p| Self::for_path(p)).collect()
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        // SAFETY: blob выделен FwpmGetAppIdFromFileName0 и освобождается один раз.
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}

/// Набор фильтров в **динамической** сессии WFP со своим подслоем. Windows удаляет
/// фильтры, когда закрывается handle движка: в Drop или при падении службы.
///
/// Подслои проверяются независимо, и блокировка в одном сильнее разрешения в
/// другом. Поэтому при смене сервера старый и новый kill switch не мешают друг
/// другу, а `DnsGuard` закрывает DNS и там, куда kill switch пускает.
struct Filters {
    engine: HANDLE,
    sublayer: GUID,
}

// SAFETY: handle движка WFP можно использовать из любого потока.
unsafe impl Send for Filters {}
unsafe impl Sync for Filters {}

impl Filters {
    /// Открывает сессию и одной транзакцией добавляет подслой и фильтры из `rules`:
    /// или всё, или ничего.
    fn install(name: &str, rules: impl FnOnce(&Filters) -> io::Result<()>) -> io::Result<Self> {
        let name = wide(name);
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            displayData: FWPM_DISPLAY_DATA0 {
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
        let filters = Filters {
            engine,
            sublayer: random_guid(),
        };

        filters.transaction(|| filters.add_sublayer(&name).and_then(|()| rules(&filters)))?;
        Ok(filters)
    }

    /// Всё из `work` — одной транзакцией: или всё, или ничего.
    fn transaction<T>(&self, work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        // SAFETY: движок открыт.
        check(
            unsafe { FwpmTransactionBegin0(self.engine, 0) },
            kvt_core::i18n::tr("транзакция", "transaction"),
        )?;
        let value = match work() {
            Ok(value) => value,
            Err(e) => {
                // SAFETY: транзакция начата выше.
                unsafe { FwpmTransactionAbort0(self.engine) };
                return Err(e);
            }
        };
        // SAFETY: транзакция начата выше.
        check(
            unsafe { FwpmTransactionCommit0(self.engine) },
            kvt_core::i18n::tr("фиксация", "commit"),
        )?;
        Ok(value)
    }

    fn add_sublayer(&self, name: &[u16]) -> io::Result<()> {
        let sub = FWPM_SUBLAYER0 {
            subLayerKey: self.sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
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
        )
    }

    fn add(
        &self,
        layer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: FWP_ACTION_TYPE,
        weight: u8,
    ) -> io::Result<()> {
        self.add_id(layer, conditions, action, weight).map(drop)
    }

    /// Добавляет фильтр и возвращает его id (для `FwpmFilterDeleteById0`).
    fn add_id(
        &self,
        layer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: FWP_ACTION_TYPE,
        weight: u8,
    ) -> io::Result<u64> {
        let name = wide("KVT");
        let mut filter = FWPM_FILTER0 {
            layerKey: layer,
            subLayerKey: self.sublayer,
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
        let mut id = 0u64;
        // SAFETY: фильтр, условия и все данные, на которые они указывают, живы
        // на время вызова; WFP копирует их внутрь.
        check(
            unsafe { FwpmFilterAdd0(self.engine, &filter, null_mut(), &mut id) },
            kvt_core::i18n::tr("фильтр", "filter"),
        )?;
        Ok(id)
    }

    fn delete(&self, id: u64) {
        // SAFETY: движок открыт, id выдан FwpmFilterAdd0 этой сессии.
        let rc = unsafe { FwpmFilterDeleteById0(self.engine, id) };
        if rc != 0 {
            tracing::warn!(code = format_args!("0x{rc:08X}"), "фильтр WFP не удалён");
        }
    }

    fn permit(
        &self,
        layer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        weight: u8,
    ) -> io::Result<()> {
        self.add(layer, conditions, FWP_ACTION_PERMIT, weight)
    }

    /// Loopback, разрешённые программы и интерфейс туннеля. Программы — только от
    /// учётной записи службы (`owner`, дескриптор из `win::own_user_sd`): тот же
    /// `xray.exe`, запущенный обычным пользователем со своим конфигом, мимо туннеля
    /// не выйдет.
    fn permit_trusted(
        &self,
        layer: GUID,
        apps: &[AppId],
        owner: &[u8],
        tun_luid: Option<u64>,
    ) -> io::Result<()> {
        self.permit(layer, &mut [loopback()], W_PERMIT)?;
        let mut sd = owner.to_vec();
        let mut owner = FWP_BYTE_BLOB {
            size: sd.len() as u32,
            data: sd.as_mut_ptr(),
        };
        for app in apps {
            self.permit(layer, &mut [app_is(app.0), user_is(&mut owner)], W_PERMIT)?;
        }
        if let Some(mut luid) = tun_luid {
            self.permit(layer, &mut [on_interface(&mut luid)], W_PERMIT)?;
        }
        Ok(())
    }

    /// Порты DNS — блок выше разрешения локальной сети.
    fn block_dns(&self, layer: GUID) -> io::Result<()> {
        for port in DNS_PORTS {
            self.add(layer, &mut [remote_port(port)], FWP_ACTION_BLOCK, W_DNS)?;
        }
        Ok(())
    }
}

impl Drop for Filters {
    fn drop(&mut self) {
        // SAFETY: движок открыт в install и закрывается один раз. Динамическая
        // сессия при закрытии удаляет все свои фильтры.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

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
fn permit_lan_v6(f: &Filters, layer: GUID) -> io::Result<()> {
    for (addr, prefix) in LAN_V6 {
        let mut mask = FWP_V6_ADDR_AND_MASK {
            addr: addr.octets(),
            prefixLength: *prefix,
        };
        f.permit(layer, &mut [remote_v6(&mut mask)], W_LAN)?;
    }
    Ok(())
}

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

fn condition(field: GUID, match_type: i32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        ..Default::default()
    }
}

fn loopback() -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET);
    c.conditionValue.r#type = FWP_UINT32;
    c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    c
}

/// Условие ссылается на `blob`: он должен жить, пока фильтр не добавлен.
fn app_is(blob: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    c.conditionValue.Anonymous.byteBlob = blob;
    c
}

/// Процесс работает от учётной записи, которой `sd` даёт право
/// `FWP_ACTRL_MATCH_FILTER`. Условие ссылается на `sd`: он должен жить, пока фильтр
/// не добавлен.
fn user_is(sd: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_ALE_USER_ID, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
    c.conditionValue.Anonymous.sd = sd;
    c
}

fn on_interface(luid: &mut u64) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT64;
    c.conditionValue.Anonymous.uint64 = luid;
    c
}

fn remote_v4(mask: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_V4_ADDR_MASK;
    c.conditionValue.Anonymous.v4AddrMask = mask;
    c
}

fn remote_v6(mask: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_V6_ADDR_MASK;
    c.conditionValue.Anonymous.v6AddrMask = mask;
    c
}

fn port_is(field: GUID, port: u16) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(field, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT16;
    c.conditionValue.Anonymous.uint16 = port;
    c
}

fn remote_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    port_is(FWPM_CONDITION_IP_REMOTE_PORT, port)
}

fn local_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    port_is(FWPM_CONDITION_IP_LOCAL_PORT, port)
}

fn udp() -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT8;
    c.conditionValue.Anonymous.uint8 = IPPROTO_UDP as u8;
    c
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

    /// Фильтры WFP действуют на весь компьютер: пока один тест держит kill switch,
    /// соседний не выйдет в сеть. Тесты с фильтрами идут по одному.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static WFP: std::sync::Mutex<()> = std::sync::Mutex::new(());
        WFP.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn connects(target: &str) -> bool {
        let target = target.parse().unwrap();
        TcpStream::connect_timeout(&target, Duration::from_secs(3)).is_ok()
    }

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
        let err = DnsGuard::enable(&[], 0, true)
            .err()
            .expect("без прав защита DNS не включается");
        assert!(err.to_string().contains("WFP"), "{err}");
    }

    /// Только из терминала администратора:
    /// `cargo test -p kvt-service kill_switch -- --ignored`
    /// Пока kill switch включён, этот процесс (его нет в списке разрешённых) не может
    /// выйти в интернет; после выключения — может.
    #[test]
    #[ignore = "нужны права администратора"]
    fn kill_switch_blocks_and_releases() {
        let _serial = serial();
        assert!(
            connects("1.1.1.1:443"),
            "нет интернета — тест не имеет смысла"
        );
        let ks = KillSwitch::enable(&[], None, false).expect("kill switch");
        assert!(!connects("1.1.1.1:443"), "kill switch пропустил соединение");
        drop(ks);
        assert!(
            connects("1.1.1.1:443"),
            "после выключения соединение должно работать"
        );
    }

    /// Только из терминала администратора:
    /// `cargo test -p kvt-service kill_switch -- --ignored`
    /// Разрешённая программа от той же учётной записи, что и служба (здесь — этот
    /// тест), выходит в сеть: условие `ALE_USER_ID` совпадает со своим SID.
    #[test]
    #[ignore = "нужны права администратора"]
    fn kill_switch_permits_app_of_own_account() {
        let _serial = serial();
        assert!(
            connects("1.1.1.1:443"),
            "нет интернета — тест не имеет смысла"
        );
        let exe = std::env::current_exe().unwrap();
        let ks = KillSwitch::enable(&[&exe], None, false).expect("kill switch");
        assert!(
            connects("1.1.1.1:443"),
            "своя программа той же учётной записи заблокирована"
        );
        drop(ks);
    }

    /// Только из терминала администратора:
    /// `cargo test -p kvt-service kill_switch -- --ignored`
    /// Адрес, открытый тестовому ядру, доступен; другие — нет; после закрытия — нет.
    #[test]
    #[ignore = "нужны права администратора"]
    fn kill_switch_probe_opens_only_given_address() {
        let _serial = serial();
        assert!(
            connects("1.1.1.1:443") && connects("8.8.8.8:443"),
            "нет интернета — тест не имеет смысла"
        );
        let exe = std::env::current_exe().unwrap();
        let mut ks = KillSwitch::enable(&[], None, false).expect("kill switch");
        assert!(!connects("1.1.1.1:443"), "kill switch пропустил соединение");
        ks.open_probe(&[&exe], &["1.1.1.1".parse().unwrap()])
            .expect("адрес открыт");
        assert!(connects("1.1.1.1:443"), "открытый адрес недоступен");
        assert!(!connects("8.8.8.8:443"), "открылся не только нужный адрес");
        ks.close_probe();
        assert!(!connects("1.1.1.1:443"), "адрес не закрылся");
        drop(ks);
    }

    /// Только из терминала администратора:
    /// `cargo test -p kvt-service dns_guard -- --ignored`
    /// Защита DNS закрывает порты 53 и 853 мимо туннеля, остальное не трогает.
    #[test]
    #[ignore = "нужны права администратора"]
    fn dns_guard_blocks_only_dns() {
        let _serial = serial();
        assert!(
            connects("1.1.1.1:53"),
            "DNS по TCP не отвечает — тест не имеет смысла"
        );
        // Туннеля в тесте нет — вместо него интерфейс, которым ничто не ходит наружу.
        let luid = interface_luid("Loopback Pseudo-Interface 1").expect("loopback");
        let guard = DnsGuard::enable(&[], luid, false).expect("защита DNS");
        assert!(!connects("1.1.1.1:53"), "DNS мимо туннеля прошёл");
        assert!(!connects("1.1.1.1:853"), "DNS-over-TLS мимо туннеля прошёл");
        assert!(connects("1.1.1.1:443"), "защита DNS закрыла не только DNS");
        drop(guard);
        assert!(
            connects("1.1.1.1:53"),
            "после выключения DNS должен работать"
        );
    }

    /// Только из терминала администратора и при работающем IPv6:
    /// `cargo test -p kvt-service dns_guard -- --ignored`
    /// TUN без IPv6: IPv6 мимо туннеля закрыт, IPv4 работает.
    #[test]
    #[ignore = "нужны права администратора"]
    fn dns_guard_blocks_ipv6_without_tun_ipv6() {
        let _serial = serial();
        const V6: &str = "[2606:4700:4700::1111]:443";
        if !connects(V6) {
            eprintln!("IPv6 у провайдера нет — проверять нечего");
            return;
        }
        let luid = interface_luid("Loopback Pseudo-Interface 1").expect("loopback");
        let guard = DnsGuard::enable(&[], luid, true).expect("защита DNS");
        assert!(!connects(V6), "IPv6 мимо туннеля прошёл");
        assert!(connects("1.1.1.1:443"), "закрылся и IPv4");
        drop(guard);
        assert!(connects(V6), "после выключения IPv6 должен работать");
    }
}
