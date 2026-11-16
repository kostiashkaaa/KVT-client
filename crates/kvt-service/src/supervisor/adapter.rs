//! Адаптер TUN и маршрут: куда сейчас идёт интернет, уборка старых адаптеров
//! Wintun, физический интерфейс для zapret.

use super::*;

/// Интернет идёт через TUN KVT: адаптер есть, и маршрут к [`ROUTE_PROBE`] ведёт в него.
pub(super) fn route_through_tun() -> bool {
    let tun = wfp::interface_index(TUN_INTERFACE);
    tun.is_some() && wfp::best_interface(ROUTE_PROBE) == tun
}

/// Физический интерфейс для winws в гибриде. Сразу после остановки прежнего ядра
/// маршрут ещё может вести в старый TUN — ждём, пока система выберет другой.
pub(super) async fn physical_interface() -> Option<u32> {
    for _ in 0..20 {
        let tun = wfp::interface_index(TUN_INTERFACE);
        match wfp::best_interface(ROUTE_PROBE) {
            Some(best) if Some(best) != tun => return Some(best),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    None
}

/// После уборки устройства Wintun интерфейс KVT исчезает не мгновенно — ждём до
/// 3 с, чтобы новое ядро не застало прежний. Интерфейса нет — возврат сразу; не
/// исчез (уборка не удалась) — запускаем всё равно: Xray откроет существующий
/// адаптер, а если упрётся в «адаптер занят», переподключит `exited`.
pub(super) async fn wait_adapter_removed() {
    const STEP: Duration = Duration::from_millis(100);
    let mut waited = Duration::ZERO;
    while wfp::interface_luid(TUN_INTERFACE).is_some() {
        if waited >= Duration::from_secs(3) {
            tracing::warn!("адаптер KVT не исчез за 3 с после остановки ядра");
            return;
        }
        tokio::time::sleep(STEP).await;
        waited += STEP;
    }
    if !waited.is_zero() {
        tracing::info!(
            ms = waited.as_millis() as u64,
            "дождались удаления адаптера KVT"
        );
    }
}

/// Устройства Wintun, оставшиеся от прежнего запуска ядра (см.
/// [`crate::win::remove_stale_wintun`]). Без этого на части компьютеров каждое
/// подключение после «Отключить» 15 с ждало Wintun и падало с «адаптер занят».
pub(super) async fn remove_stale_wintun_devices() {
    let results = tokio::task::spawn_blocking(|| {
        crate::win::KVT_WINTUN_DEVICES
            .iter()
            .map(|id| (*id, crate::win::remove_stale_wintun(id)))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    for (device, result) in results {
        match result {
            Ok(true) => tracing::info!(device, "убрано оставшееся устройство Wintun"),
            Ok(false) => {}
            // Не мешает подключению: ядро попробует само, а при сбое KVT переподключится.
            Err(e) => tracing::warn!(device, error = %e, "не удалось убрать устройство Wintun"),
        }
    }
}
