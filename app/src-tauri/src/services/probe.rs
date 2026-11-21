//! Один запрос к сервису: обычный HTTPS-запрос окна, без прокси и без особого
//! канала. Он идёт по тому пути, по которому пойдёт трафик самого пользователя
//! (туннель, zapret или напрямую) — иначе «открывается» ничего бы не доказывало.
//!
//! Ответ с любым кодом HTTP — «достучались» (страница-заглушка провайдера по HTTPS
//! приходит обрывом, а не кодом). Тело читается до `SAMPLE_BYTES`: дальше окна, где
//! ТСПУ обрывает поток.

use kvt_core::netlog::{self, Origin, Outcome, Purpose, Route};
use kvt_core::services::{classify, Health, Probe, Sample, SAMPLE_BYTES};
use std::time::{Duration, Instant};
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Сколько ждём заголовки ответа после соединения.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);
/// Пауза в потоке, после которой считаем, что его оборвали.
const STALL: Duration = Duration::from_secs(4);
/// Дольше тело не читаем: данные идут, но слишком медленно.
const READ_LIMIT: Duration = Duration::from_secs(10);

/// Каждая проба открывает новое соединение (иначе проверялось бы прошлое, а не
/// рукопожатие), перенаправления не идут: новый хост — это новый SNI мимо
/// NetGovernor. Код 3xx — тоже ответ.
pub(super) fn client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_max_idle_per_host(0)
        .build()
}

/// Запрос, вердикт и запись в журнал.
pub(super) async fn run(client: &reqwest::Client, probe: &Probe) -> Health {
    let started = Instant::now();
    let health = classify(&sample(client, &probe.url).await);
    let outcome = match health {
        Health::Works | Health::Slow => Outcome::Ok,
        Health::Down(_) => Outcome::Failed,
    };
    netlog::record(
        netlog::Event::new(
            Origin::App,
            Purpose::Service,
            &probe.host,
            // По правилам маршрутизации, если подключён VPN.
            Route::Direct,
            outcome,
        )
        .ms(started.elapsed())
        .detail(health.message()),
    );
    health
}

async fn sample(client: &reqwest::Client, url: &str) -> Sample {
    let mut s = Sample {
        dns_resolved: true,
        ..Sample::default()
    };
    let start = Instant::now();
    let mut response = match timeout(RESPONSE_TIMEOUT, client.get(url).send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            s.dns_resolved = !is_dns_error(&e);
            return s;
        }
        Err(_) => return s,
    };
    s.answered = true;
    s.first_byte = Some(start.elapsed());
    let read_start = Instant::now();
    loop {
        match timeout(STALL, response.chunk()).await {
            Ok(Ok(Some(chunk))) => s.bytes += chunk.len() as u64,
            // Тело кончилось раньше порога — значит, не обрывали.
            Ok(Ok(None)) => {
                s.complete = true;
                break;
            }
            // Оборвалось или встало.
            _ => break,
        }
        if s.bytes >= SAMPLE_BYTES {
            s.complete = true;
            break;
        }
        if read_start.elapsed() > READ_LIMIT {
            s.timed_out = true;
            break;
        }
    }
    s.read = read_start.elapsed();
    s
}

/// Ошибка запроса — «имя не нашлось». Текст ошибки reqwest в журнал не идёт: в нём
/// адрес запроса, а нужна только эта проверка.
fn is_dns_error(e: &reqwest::Error) -> bool {
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(inner) = source {
        text.push(' ');
        text.push_str(&inner.to_string());
        source = inner.source();
    }
    mentions_dns(&text)
}

fn mentions_dns(text: &str) -> bool {
    let text = text.to_lowercase();
    // hyper: «dns error: failed to lookup address information»; Windows: код 11001.
    [
        "dns error",
        "failed to lookup",
        "no such host",
        "os error 11001",
    ]
    .iter()
    .any(|m| text.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_failures_are_told_from_other_connect_errors() {
        assert!(mentions_dns(
            "error sending request: error trying to connect: dns error: failed to lookup address information"
        ));
        assert!(mentions_dns("No such host is known. (os error 11001)"));
        assert!(!mentions_dns(
            "error trying to connect: tcp connect error: connection refused (os error 10061)"
        ));
        assert!(!mentions_dns("operation timed out"));
        assert!(!mentions_dns(""));
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable_not_dns() {
        // Никто не слушает: соединение отвергается сразу, имя при этом находится
        // (`localhost`), значит, это «не соединилось», а не «нет адреса».
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let client = client().unwrap();
        let s = sample(&client, &format!("https://localhost:{port}/")).await;
        assert!(s.dns_resolved);
        assert!(!s.answered);
        assert_eq!(
            classify(&s),
            Health::Down(kvt_core::services::Cause::Unreachable)
        );
    }

    #[tokio::test]
    async fn unknown_name_is_dns() {
        // Зарезервированный домен `.invalid` (RFC 6761) не разрешается нигде.
        let client = client().unwrap();
        let s = sample(&client, "https://kvt-test.invalid/").await;
        assert_eq!(classify(&s), Health::Down(kvt_core::services::Cause::Dns));
    }
}
