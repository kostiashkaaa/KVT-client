//! «Проверить VPN»: с какого адреса и из какой страны видят снаружи, и какая
//! скорость — через VPN и напрямую. Источники — по порядку, пока один не
//! ответит (`routing::TRACE_URLS` и `SPEED_URLS`): Cloudflare может быть
//! недоступен из России, запасные — sypexgeo (российский), ipwho.is и файл OVH.
//! Через туннель их ведёт системное правило (`PROBE_HOSTS`), «напрямую» — сокет
//! с адреса физического адаптера под `NetGovernor`, как у проверки одного
//! сайта; kill switch закрывает этот путь — строки «не проверяли». Каждый
//! запрос — с записью в журнал.

use crate::{netinfo, AppState};
use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::routing::{SPEED_URLS, TRACE_URLS};
use kvt_core::sitecheck::{self, Path};
use kvt_core::vpncheck::{self, Side, SideView};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tauri::State;

/// Запрос адреса дольше — источник не отвечает (как у проверки туннеля).
const TRACE_TIMEOUT: Duration = Duration::from_secs(8);
/// Сколько качаем для замера скорости: достаточно и на медленной линии.
const SPEED_WINDOW: Duration = Duration::from_secs(5);
/// Пауза в скачивании дольше — поток замер, скорость не называем.
const SPEED_STALL: Duration = Duration::from_secs(4);
/// Сколько ждать допуска `NetGovernor` для прямой пробы (его пауза — 2 с).
const GOVERNOR_WAIT: Duration = Duration::from_secs(5);

#[tauri::command]
pub async fn vpn_check(state: State<'_, AppState>) -> Result<vpncheck::Report, String> {
    let (running, kill_switch) = crate::sitecheck::detect(&state).await;
    let (paths, skipped) = sitecheck::plan_paths(running, kill_switch);

    let mut sides = Vec::new();
    for path in paths {
        let side = measure(&state, path).await;
        sides.push(vpncheck::PathSide { path, side });
    }
    Ok(vpncheck::Report {
        running,
        sides,
        skipped: skipped
            .into_iter()
            .map(|(path, reason)| sitecheck::SkippedPath { path, reason })
            .collect(),
    })
}

/// Допуск `NetGovernor` для прямой пробы; через туннель лимит не нужен (как у
/// проверки туннеля).
async fn admitted(state: &AppState, path: Path, host: &str) -> bool {
    match path {
        Path::Tunnel => true,
        Path::Direct => {
            crate::fetch::acquire_for(&state.governor, host, Purpose::Service, GOVERNOR_WAIT)
                .await
                .is_ok()
        }
    }
}

/// Один путь: адрес и страна, затем замер скорости. Источники пробуются по
/// порядку: замена нужна тогда, когда основной недоступен, а не всегда.
async fn measure(state: &AppState, path: Path) -> Side {
    let src = match path {
        Path::Tunnel => None,
        Path::Direct => tokio::task::spawn_blocking(netinfo::physical_ipv4)
            .await
            .ok()
            .flatten(),
    };

    // Адрес и страна.
    let mut deferred = false;
    let mut answered: Option<(Option<String>, Option<String>, u64, &'static str)> = None;
    for (url, source) in TRACE_URLS {
        let host = netlog::host_of(url);
        if !admitted(state, path, &host).await {
            deferred = true;
            continue;
        }
        match trace(src, url, source).await {
            Ok((ip, country, ms)) => {
                log(
                    path,
                    &host,
                    true,
                    "адрес выхода",
                    Some(Duration::from_millis(ms)),
                );
                answered = Some((ip, country, ms, source));
                break;
            }
            Err(()) => {
                log(path, &host, false, "адрес выхода", None);
            }
        }
    }
    let Some((ip, country, ms, trace_via)) = answered else {
        // Ни один источник не ответил; без допуска — «отложено», иначе «не удалось».
        return if deferred {
            Side::Deferred
        } else {
            Side::Failed
        };
    };

    // Скорость: следующий источник пробуем и тогда, когда данные замерли —
    // замер на обрыве не показывает скорость.
    let mut kbps = None;
    let mut speed_via = None;
    for (url, source) in SPEED_URLS {
        let host = netlog::host_of(url);
        if !admitted(state, path, &host).await {
            continue;
        }
        let (measured, ms) = speed(src, url).await;
        log(path, &host, measured.is_some(), "замер скорости", ms);
        if let Some(measured) = measured {
            kbps = Some(measured);
            speed_via = Some(source);
            break;
        }
    }

    Side::Ok(Box::new(SideView {
        ip,
        country,
        kbps,
        ms: Some(ms),
        trace_via: Some(trace_via.to_string()),
        speed_via: speed_via.map(|v| v.to_string()),
    }))
}

/// Адрес и страна выхода: у Cloudflare ответ — строки, у запасных — JSON,
/// разбирает `kvt_core::vpncheck` по подписи источника.
async fn trace(
    src: Option<Ipv4Addr>,
    url: &str,
    source: &str,
) -> Result<(Option<String>, Option<String>, u64), ()> {
    let client = client(src);
    let start = Instant::now();
    let response = client
        .get(url)
        .timeout(TRACE_TIMEOUT)
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let body = response.text().await.map_err(|_| ())?;
    let (ip, country) = vpncheck::parse_trace(source, &body);
    Ok((ip, country, start.elapsed().as_millis() as u64))
}

/// Замер скорости: читаем ответ до конца окна (5 с), пауза дольше `SPEED_STALL` —
/// поток замер. `None` — замер не удался, пробуем следующий источник.
async fn speed(src: Option<Ipv4Addr>, url: &str) -> (Option<u64>, Option<Duration>) {
    let Ok(mut response) = client(src).get(url).send().await else {
        return (None, None);
    };
    if !response.status().is_success() {
        return (None, None);
    }
    let start = Instant::now();
    let mut bytes = 0u64;
    let mut stalled = false;
    loop {
        if start.elapsed() >= SPEED_WINDOW {
            break;
        }
        match tokio::time::timeout(SPEED_STALL, response.chunk()).await {
            Ok(Ok(Some(chunk))) => bytes += chunk.len() as u64,
            // EOF или ошибка — закончили; пауза — поток замер.
            Ok(Ok(None)) | Ok(Err(_)) => break,
            Err(_) => {
                stalled = true;
                break;
            }
        }
    }
    let elapsed = start.elapsed();
    let kbps = if stalled {
        None
    } else {
        vpncheck::kbps(bytes, elapsed.as_millis() as u64)
    };
    (kbps, Some(elapsed))
}

/// Клиент одной пробы: новое соединение (иначе измерялся бы прошлый путь),
/// системный прокси не используется. «Напрямую» — с адреса физического адаптера.
fn client(src: Option<Ipv4Addr>) -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .local_address(src.map(IpAddr::V4))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap_or_default()
}

/// Одна проба — одна строка журнала: через туннель — как проверка туннеля,
/// «напрямую» — как пробы сервисов.
fn log(path: Path, host: &str, ok: bool, what: &str, ms: Option<Duration>) {
    let (purpose, route) = match path {
        Path::Tunnel => (Purpose::Tunnel, Route::Tunnel),
        Path::Direct => (Purpose::Service, Route::Direct),
    };
    let outcome = if ok { Outcome::Ok } else { Outcome::Failed };
    let mut event = netlog::Event::new(Origin::App, purpose, host, route, outcome);
    if let Some(ms) = ms {
        event = event.ms(ms);
    }
    netlog::record(event.detail(what));
}
