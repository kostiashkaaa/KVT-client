//! Сессия WFP и набор фильтров: динамическая сессия со своим подслоем, добавление
//! фильтров одной транзакцией, идентификаторы приложений.

use super::conditions::*;
use super::{DNS_PORTS, W_DNS, W_PERMIT};
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_UINT8,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

pub(super) fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

pub(super) fn check(code: u32, what: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(kvt_core::trf!(
            "WFP {what}: код 0x{code:08X}",
            "WFP {what}: code 0x{code:08X}"
        )))
    }
}

/// Идентификатор приложения для условий WFP; память освобождается в Drop.
pub(super) struct AppId(pub(super) *mut FWP_BYTE_BLOB);

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

    pub(super) fn for_paths(paths: &[&Path]) -> io::Result<Vec<Self>> {
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
pub(super) struct Filters {
    engine: HANDLE,
    sublayer: GUID,
}

// SAFETY: handle движка WFP можно использовать из любого потока.
unsafe impl Send for Filters {}
unsafe impl Sync for Filters {}

impl Filters {
    /// Открывает сессию и одной транзакцией добавляет подслой и фильтры из `rules`:
    /// или всё, или ничего.
    pub(super) fn install(
        name: &str,
        rules: impl FnOnce(&Filters) -> io::Result<()>,
    ) -> io::Result<Self> {
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
    pub(super) fn transaction<T>(&self, work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
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

    pub(super) fn add(
        &self,
        layer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: FWP_ACTION_TYPE,
        weight: u8,
    ) -> io::Result<()> {
        self.add_id(layer, conditions, action, weight).map(drop)
    }

    /// Добавляет фильтр и возвращает его id (для `FwpmFilterDeleteById0`).
    pub(super) fn add_id(
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

    pub(super) fn delete(&self, id: u64) {
        // SAFETY: движок открыт, id выдан FwpmFilterAdd0 этой сессии.
        let rc = unsafe { FwpmFilterDeleteById0(self.engine, id) };
        if rc != 0 {
            tracing::warn!(code = format_args!("0x{rc:08X}"), "фильтр WFP не удалён");
        }
    }

    pub(super) fn permit(
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
    pub(super) fn permit_trusted(
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
    pub(super) fn block_dns(&self, layer: GUID) -> io::Result<()> {
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
