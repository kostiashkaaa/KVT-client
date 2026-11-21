//! «Почему не работает?» для одного сайта: сбор фактов. Пробы идут по стадиям —
//! имя → TCP → TLS → ответ → данные — каждым доступным путём (через туннель и
//! напрямую, с адреса физического адаптера). Вердикты, доступные пути и совет —
//! `kvt_core::sitecheck`, там их проверяют тесты; здесь — запросы.
//!
//! Каждая проба — исходящее соединение: через `NetGovernor` (`Purpose::Service`,
//! как у плиток сервисов — та же природа запроса), с записью в журнал; заморозка —
//! `report_freeze`, чтобы повторная проверка не продлевала её. Проба каждого пути —
//! новое соединение: иначе проверялся бы прошлый путь.

use crate::{netinfo, AppState};
use kvt_core::ipc::ServiceStatus;
use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::sitecheck::{self, Path, Running, Stages, TlsStage};
use std::time::{Duration, Instant};
use tauri::State;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// TCP-соединение дольше — «адрес недоступен» (как у плиток сервисов).
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
/// Рукопожатие дольше — «заморозили»: на ClientHello не ответили вовремя.
const TLS_TIMEOUT: Duration = Duration::from_secs(8);
/// Первая строка ответа дольше — данных нет.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);
/// Пауза в чтении дольше — поток замер или оборвали.
const STALL: Duration = Duration::from_secs(4);
/// Чтение тела дольше — «медленно», но не обрыв.
const READ_LIMIT: Duration = Duration::from_secs(10);
/// Сколько тела читаем: дальше окна заморозки ТСПУ, как у плиток сервисов.
const SAMPLE_BYTES: usize = 64 * 1024;
/// Сколько адресов имени пробуем по TCP: у сайта их бывает несколько.
const MAX_ADDRS: usize = 3;
/// Пауза `NetGovernor` между путями (2 с) — сколько готовы подождать допуска.
const GOVERNOR_WAIT: Duration = Duration::from_secs(5);
/// Строка как у Edge: отпечаток и так системный (Schannel), пусть и заголовки
/// будут как у браузера — отказ не должен выглядеть как чужая проба.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";

#[tauri::command]
pub async fn site_check(
    input: String,
    state: State<'_, AppState>,
) -> Result<sitecheck::Report, String> {
    let target = sitecheck::Target::try_from(input.as_str())?;
    let host = target.host().to_string();

    // Что работает и включён ли kill switch — как у плиток сервисов: смотрим
    // статус службы и план, с которым подключились, а не выбранный режим.
    let (running, kill_switch) = detect(&state).await;
    let (paths, skipped) = sitecheck::plan_paths(running, kill_switch);

    let mut reports = Vec::new();
    for path in paths {
        let started = Instant::now();
        // Один сайт — один SNI: второй путь ждёт паузу губернатора. Заморозка
        // (наша или ТСПУ) не выжидается — «попробуйте позже» честнее.
        if crate::fetch::acquire_for(&state.governor, &host, Purpose::Service, GOVERNOR_WAIT)
            .await
            .is_err()
        {
            reports.push(report(path, None, started));
            continue;
        }
        let verdict = probe(&host, path).await;
        log_verdict(&host, path, verdict, started);
        if verdict.is_freeze() {
            // Заморозку записываем на имя сайта: так же, как проверки серверов.
            if let Ok(mut g) = state.governor.lock() {
                g.report_freeze(&host, Instant::now());
            }
        }
        reports.push(report(path, Some(verdict), started));
    }

    let results: Vec<(Path, sitecheck::Verdict)> = reports
        .iter()
        .filter_map(|r| r.verdict.map(|v| (r.path, v)))
        .collect();
    Ok(sitecheck::Report {
        host,
        running,
        paths: reports,
        skipped: skipped
            .into_iter()
            .map(|(path, reason)| sitecheck::SkippedPath { path, reason })
            .collect(),
        advice: sitecheck::conclude(running, &results),
    })
}

fn report(
    path: Path,
    verdict: Option<sitecheck::Verdict>,
    started: Instant,
) -> sitecheck::PathReport {
    sitecheck::PathReport {
        path,
        verdict,
        ms: Some(started.elapsed().as_millis() as u64),
    }
}

/// Что сейчас работает и включён ли kill switch.
async fn detect(state: &AppState) -> (Running, bool) {
    let kill_switch = state.choice.lock().map(|c| c.kill_switch).unwrap_or(false);
    let running = match crate::query_status().await.ok().flatten() {
        Some(ServiceStatus::Connected { .. }) => {
            let hybrid = crate::services::connected_plan(state).is_some_and(|(_, h)| h);
            if hybrid {
                Running::Hybrid
            } else {
                Running::Vpn
            }
        }
        Some(ServiceStatus::Zapret { .. }) => Running::Zapret,
        _ => Running::Off,
    };
    (running, kill_switch)
}

/// Одна проба одним путём: стадии по порядку, каждая со своим таймаутом.
async fn probe(host: &str, path: Path) -> sitecheck::Verdict {
    let mut s = Stages::default();
    // Мимо туннеля — с адреса физического адаптера; при работающем zapret перехват
    // winws действует и на эту пробу — это и есть путь «через zapret». Kill switch
    // такой путь закрывает — `plan_paths` его не предлагает.
    let src = match path {
        Path::Tunnel => None,
        Path::Direct => tokio::task::spawn_blocking(netinfo::physical_ipv4)
            .await
            .ok()
            .flatten(),
    };

    // Имя узнаёт системный резолвер: при работающем VPN — через туннель (DNS мимо
    // него закрыт). Для «напрямую» это не меняет вердикта: режут путь, а не адрес.
    let addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host((host, 443)).await {
        Ok(all) => all
            .filter(|a| src.is_none() || a.is_ipv4())
            .take(MAX_ADDRS)
            .collect(),
        Err(_) => Vec::new(),
    };
    s.dns = !addrs.is_empty();

    // TCP: первый открывшийся адрес.
    let mut tcp = None;
    for addr in &addrs {
        let connect = async {
            match src {
                Some(src) => {
                    let socket = TcpSocket::new_v4()?;
                    socket.bind(std::net::SocketAddr::from((src, 0)))?;
                    socket.connect(*addr).await
                }
                None => TcpStream::connect(*addr).await,
            }
        };
        if let Ok(Ok(stream)) = tokio::time::timeout(TCP_TIMEOUT, connect).await {
            tcp = Some(stream);
            break;
        }
    }
    s.tcp = tcp.is_some();
    let Some(tcp) = tcp else {
        return sitecheck::classify(&s);
    };

    // TLS: Schannel — системный отпечаток как у Edge, SNI ставится по имени.
    let Ok(connector) = native_tls::TlsConnector::new().map(tokio_native_tls::TlsConnector::from)
    else {
        return sitecheck::classify(&s);
    };
    s.tls = match tokio::time::timeout(TLS_TIMEOUT, connector.connect(host, tcp)).await {
        // Замолчали на ClientHello — заморозка.
        Err(_) => TlsStage::Frozen,
        // Обрыв или ошибка рукопожатия: режут по имени. Сюда же попадает редкая
        // ошибка сертификата — честнее сказать «оборвали», чем «работает».
        Ok(Err(_)) => TlsStage::Cut,
        Ok(Ok(tls)) => {
            read_http(tls, host, &mut s).await;
            TlsStage::Done
        }
    };
    sitecheck::classify(&s)
}

/// HTTP-ответ по готовому TLS-потоку: строка статуса, затем тело — до конца,
/// до лимита чтения или до замера.
async fn read_http(mut tls: tokio_native_tls::TlsStream<TcpStream>, host: &str, s: &mut Stages) {
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: ru,en;q=0.9\r\nConnection: close\r\n\r\n"
    );
    // Не смогли отправить — поток оборвали сразу после рукопожатия.
    if tokio::time::timeout(RESPONSE_TIMEOUT, tls.write_all(request.as_bytes()))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        return;
    }

    let started = Instant::now();
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if buf.len() >= SAMPLE_BYTES {
            s.complete = true;
            break;
        }
        if started.elapsed() > READ_LIMIT {
            s.stalled = true;
            break;
        }
        // Пауза в потоке — замер; обрыв читается как ошибка чтения — тоже.
        match tokio::time::timeout(STALL, tls.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                s.complete = true;
                break;
            }
            Ok(Ok(n)) => {
                if s.first_byte_ms.is_none() {
                    s.first_byte_ms = Some(started.elapsed().as_millis() as u64);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Ok(Err(_)) | Err(_) => {
                s.stalled = true;
                break;
            }
        }
    }

    // Заголовки кончаются пустой строкой; статус — во второй части первой строки.
    if let Some(at) = find_header_end(&buf) {
        s.status = parse_status(&buf[..at]);
        s.bytes = (buf.len() - at - 4) as u64;
        s.read_ms = started.elapsed().as_millis() as u64;
    }
}

/// Где кончаются заголовки: позиция `\r\n\r\n`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Код из строки статуса: `HTTP/1.1 403 Forbidden` → 403.
fn parse_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let Ok(text) = std::str::from_utf8(line.trim_ascii()) else {
        return None;
    };
    text.split_ascii_whitespace().nth(1)?.parse().ok()
}

/// Проба одного пути в журнал запросов: имя — суть записи, вердикт — в подробности.
fn log_verdict(host: &str, path: Path, verdict: sitecheck::Verdict, started: Instant) {
    let route = match path {
        Path::Tunnel => Route::Tunnel,
        Path::Direct => Route::Direct,
    };
    let outcome = match verdict {
        sitecheck::Verdict::Works | sitecheck::Verdict::Slow => Outcome::Ok,
        _ => Outcome::Failed,
    };
    netlog::record(
        netlog::Event::new(Origin::App, Purpose::Service, host, route, outcome)
            .detail(verdict.message())
            .ms(started.elapsed()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_is_parsed_from_the_first_header_line() {
        assert_eq!(
            parse_status(b"HTTP/1.1 403 Forbidden\r\nServer: x"),
            Some(403)
        );
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.1\r\n"), None);
        assert_eq!(parse_status(b"\xff\xfe garbage\r\n"), None);
    }

    #[test]
    fn header_end_is_found_after_the_blank_line() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\nbody"), Some(15));
        assert_eq!(find_header_end(b"no headers yet"), None);
    }
}
