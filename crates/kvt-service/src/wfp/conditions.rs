//! Условия фильтров WFP: loopback, приложение, пользователь, интерфейс, адрес, порт, UDP.

use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_EQUAL,
    FWP_MATCH_FLAGS_ALL_SET, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT32, FWP_UINT64,
    FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
};
use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;

pub(super) fn condition(field: GUID, match_type: i32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        ..Default::default()
    }
}

pub(super) fn loopback() -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET);
    c.conditionValue.r#type = FWP_UINT32;
    c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    c
}

/// Условие ссылается на `blob`: он должен жить, пока фильтр не добавлен.
pub(super) fn app_is(blob: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    c.conditionValue.Anonymous.byteBlob = blob;
    c
}

/// Процесс работает от учётной записи, которой `sd` даёт право
/// `FWP_ACTRL_MATCH_FILTER`. Условие ссылается на `sd`: он должен жить, пока фильтр
/// не добавлен.
pub(super) fn user_is(sd: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_ALE_USER_ID, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
    c.conditionValue.Anonymous.sd = sd;
    c
}

pub(super) fn on_interface(luid: &mut u64) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT64;
    c.conditionValue.Anonymous.uint64 = luid;
    c
}

pub(super) fn remote_v4(mask: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_V4_ADDR_MASK;
    c.conditionValue.Anonymous.v4AddrMask = mask;
    c
}

pub(super) fn remote_v6(mask: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_V6_ADDR_MASK;
    c.conditionValue.Anonymous.v6AddrMask = mask;
    c
}

pub(super) fn port_is(field: GUID, port: u16) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(field, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT16;
    c.conditionValue.Anonymous.uint16 = port;
    c
}

pub(super) fn remote_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    port_is(FWPM_CONDITION_IP_REMOTE_PORT, port)
}

pub(super) fn local_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    port_is(FWPM_CONDITION_IP_LOCAL_PORT, port)
}

pub(super) fn udp() -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT8;
    c.conditionValue.Anonymous.uint8 = IPPROTO_UDP as u8;
    c
}

pub(super) fn random_guid() -> GUID {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    GUID::from_u128(nanos ^ (u128::from(std::process::id()) << 96))
}
