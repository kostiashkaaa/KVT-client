//! «Почему не работает?» для одного сайта: типы и выводы без сети. Пробы по стадиям
//! (имя → TCP → TLS → ответ → данные) каждым доступным путём делает окно
//! (`sitecheck` в `kvt-app`); здесь — проверка адреса, какие пути доступны,
//! как по наблюдениям понять, как именно режут, и что посоветовать. Как у плиток
//! сервисов: сбор фактов в окне, выводы — здесь, и их проверяют тесты.

use crate::i18n::tr;
use serde::Serialize;
use std::net::Ipv4Addr;

/// Окно заморозки данных ТСПУ: поток замирает вскоре после начала. Для сайта
/// любой замер или обрыв без конца ответа — «данные не идут»; объём не решает.
/// Ответ дольше — «медленно» (как у плиток сервисов).
const SLOW_FIRST_BYTE_MS: u64 = 3_000;
/// Тело читается дольше — «медленно».
const SLOW_READ_MS: u64 = 3_000;

/// Проверяемый сайт: домен или публичный IP, без схемы, логина, порта и пути.
/// Разбирается как чужой ввод: частные и локальные адреса не проверяем — окно
/// не ходит в свою сеть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target(String);

impl TryFrom<&str> for Target {
    type Error = String;

    fn try_from(input: &str) -> Result<Self, String> {
        let bad = || {
            tr(
                "Не похоже на адрес сайта. Пример: example.com",
                "Doesn't look like a site address. Example: example.com",
            )
            .to_string()
        };
        let local = || {
            tr(
                "Локальные и частные адреса не проверяем.",
                "Local and private addresses aren't checked.",
            )
            .to_string()
        };
        // Как в «Маршрутизации»: срезаем схему, путь, логин и порт, оставляя имя.
        let mut host = input.trim().to_ascii_lowercase();
        if let Some((_, rest)) = host.split_once("://") {
            host = rest.to_string();
        }
        host = host
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .to_string();
        if host.contains(':') {
            // Порт в конце срезаем; IPv6-литерал в скобках не проверяем вовсе.
            if host.starts_with('[') {
                return Err(local());
            }
            host = host.rsplit_once(':').map_or(host.to_string(), |(h, p)| {
                if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() {
                    h.to_string()
                } else {
                    host.to_string()
                }
            });
        }
        if host.is_empty() || host.len() > 253 {
            return Err(bad());
        }
        if crate::zapret::valid_domain(&host)
            && !is_localhost(&host)
            // Домен сайта — с точкой и буквенной последней меткой: «1.2.3» и
            // имена без TLD — это не сайт, а что-то в чужой или своей сети.
            && host.rsplit('.').next().is_some_and(|tld| tld.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
        {
            return Ok(Target(host));
        }
        match host.parse::<Ipv4Addr>() {
            Ok(ip) if !local_v4(ip) => Ok(Target(host)),
            Ok(_) => Err(local()),
            Err(_) => Err(bad()),
        }
    }
}

/// Адрес этого компьютера или локальной сети: просить окно сходить туда нечего.
/// Те же признаки, что у отказа локальных ссылок в `fetch` (окно).
fn local_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
}

fn is_localhost(domain: &str) -> bool {
    domain == "localhost" || domain.ends_with(".localhost")
}

impl Target {
    /// Имя в нижнем регистре: оно же уходит в SNI и в `NetGovernor`.
    pub fn host(&self) -> &str {
        &self.0
    }
}

/// Итог стадии TLS: обрыв и молчание — разные способы резать.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsStage {
    /// До стадии не дошли: раньше не вышло.
    #[default]
    Skipped,
    /// Рукопожатие прошло.
    Done,
    /// Соединение оборвали сразу после ClientHello — режут по имени сайта.
    Cut,
    /// На ClientHello нет ответа — соединение заморозили.
    Frozen,
}

/// Что увидела одна проба по стадиям. Стадии идут по порядку; на первой неудаче
/// дальше не ходим, поэтому `false`/`None` — «дошли и не вышло», а не «не проверяли».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stages {
    /// Имя превратилось в адрес.
    pub dns: bool,
    /// TCP-соединение открылось.
    pub tcp: bool,
    pub tls: TlsStage,
    /// HTTP-код ответа.
    pub status: Option<u16>,
    /// Ждали ответа столько (до первой строки ответа).
    pub first_byte_ms: Option<u64>,
    /// Прочитано тела, байт.
    pub bytes: u64,
    /// Поток замер: пауза длиннее `stall` в чтении.
    pub stalled: bool,
    /// Ответ дочитан: сервер закрыл соединение или дошли до лимита чтения.
    pub complete: bool,
    /// От первой строки ответа до последнего байта.
    pub read_ms: u64,
}

/// Вердикт одной пробы: как именно отвечает (или режет) этот путь.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// У имени нет адреса.
    NoAddress,
    /// TCP не открывается: адрес недоступен или его заблокировали.
    Unreachable,
    /// Соединение оборвали — режут по имени сайта (SNI): на рукопожатии или
    /// сразу после него, до ответа.
    TlsCut,
    /// На рукопожатие нет ответа — соединение заморозили.
    TlsFrozen,
    /// Поток замер или был оборван, не дойдя до конца: данные не идут.
    DataFrozen,
    /// Соединение живое, но сайт сам не пускает (403/451 — обычно не та страна).
    Refused,
    /// Открывается, но медленно.
    Slow,
    /// Открывается.
    Works,
}

impl Verdict {
    /// Короткая подпись для журнала (`netlog`).
    pub fn message(self) -> &'static str {
        match self {
            Verdict::NoAddress => tr("у имени нет адреса", "the name has no address"),
            Verdict::Unreachable => tr("TCP не открылся", "TCP didn't open"),
            Verdict::TlsCut => tr("соединение оборвали", "the connection was cut"),
            Verdict::TlsFrozen => tr("рукопожатие заморожено", "the handshake was frozen"),
            Verdict::DataFrozen => tr("данные заморожены", "data was frozen"),
            Verdict::Refused => tr("сайт не пускает", "the site refuses"),
            Verdict::Slow => tr("отвечает медленно", "responds slowly"),
            Verdict::Works => tr("открывается", "opens"),
        }
    }

    /// Заморозка: о ней сообщаем `NetGovernor`, чтобы следующие пробы не продлевали её.
    pub fn is_freeze(self) -> bool {
        matches!(self, Verdict::TlsFrozen | Verdict::DataFrozen)
    }
}

/// Вердикт по наблюдениям пробы. Порядок — от ранней стадии к поздней: что
/// первое не вышло, то и ответ.
pub fn classify(s: &Stages) -> Verdict {
    if !s.dns {
        return Verdict::NoAddress;
    }
    if !s.tcp {
        return Verdict::Unreachable;
    }
    match s.tls {
        TlsStage::Skipped => return Verdict::Unreachable,
        TlsStage::Cut => return Verdict::TlsCut,
        TlsStage::Frozen => return Verdict::TlsFrozen,
        TlsStage::Done => {}
    }
    if matches!(s.status, Some(403) | Some(451)) {
        return Verdict::Refused;
    }
    // Ответа нет вовсе: замолчали — данные не идут, оборвали — режут по имени.
    if s.status.is_none() {
        return if s.stalled {
            Verdict::DataFrozen
        } else {
            Verdict::TlsCut
        };
    }
    // Поток замер или был оборван, не дойдя до конца, — данных нет.
    if !s.complete && s.stalled {
        return Verdict::DataFrozen;
    }
    if s.first_byte_ms.is_some_and(|ms| ms > SLOW_FIRST_BYTE_MS) || s.read_ms > SLOW_READ_MS {
        return Verdict::Slow;
    }
    Verdict::Works
}

/// Что сейчас работает — как у плиток сервисов (`services`), но без деталей плана:
/// для пробы важен только доступный путь.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Running {
    Off,
    Vpn,
    Hybrid,
    Zapret,
}

/// Каким путём идёт проба.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Path {
    /// Системные маршруты: при работающем VPN — через туннель.
    Tunnel,
    /// Мимо туннеля, с адреса физического адаптера. При работающем zapret
    /// перехват winws действует и на эту пробу — это и есть путь «через zapret».
    Direct,
}

/// Почему путь не проверяли.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Kill switch держит трафик в туннеле: проба мимо него не пройдёт.
    KillSwitch,
}

/// Какие пути проверять и почему остальные пропущены. Kill switch важен только
/// при работающем VPN: без него трафик и так идёт как идёт.
pub fn plan_paths(running: Running, kill_switch: bool) -> (Vec<Path>, Vec<(Path, SkipReason)>) {
    match running {
        Running::Off | Running::Zapret => (vec![Path::Direct], Vec::new()),
        Running::Vpn | Running::Hybrid if kill_switch => (
            vec![Path::Tunnel],
            vec![(Path::Direct, SkipReason::KillSwitch)],
        ),
        Running::Vpn | Running::Hybrid => (vec![Path::Tunnel, Path::Direct], Vec::new()),
    }
}

/// Совет по итогам всех проб: короткий, одной строкой; детали — в вердиктах путей.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Advice {
    /// Открывается хотя бы одним путём — каким, видно в вердиктах.
    Works,
    /// Режут все доступные пути, VPN не подключён — попробовать VPN.
    TryVpn,
    /// Режут и через VPN — дело в сервере или в самом сайте.
    StillCut,
    /// Сайт не пускает с этого адреса (403 при живом соединении) — сменить сервер.
    ChangeServer,
    /// Имя не находится ни одним путём — проверить DNS.
    CheckDns,
}

pub fn conclude(running: Running, results: &[(Path, Verdict)]) -> Advice {
    if results
        .iter()
        .any(|(_, v)| matches!(v, Verdict::Works | Verdict::Slow))
    {
        return Advice::Works;
    }
    if results.iter().all(|(_, v)| *v == Verdict::NoAddress) {
        return Advice::CheckDns;
    }
    // VPN не работает (или только zapret): «напрямую» проверено, туннель — нет.
    if matches!(running, Running::Off | Running::Zapret) {
        return Advice::TryVpn;
    }
    if results.iter().any(|(_, v)| *v == Verdict::Refused) {
        return Advice::ChangeServer;
    }
    Advice::StillCut
}

/// Одна проба одним путём: `None` — `NetGovernor` отложил соединение
/// (заморозка после прошлых проб, повтор позже).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathReport {
    pub path: Path,
    pub verdict: Option<Verdict>,
    /// Сколько шла проба (от соединения до вердикта).
    pub ms: Option<u64>,
}

/// Путь, который не проверяли, и почему.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedPath {
    pub path: Path,
    pub reason: SkipReason,
}

/// Итог проверки одного сайта для окна.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Имя, как его проверяли (в нижнем регистре, без пути и порта).
    pub host: String,
    pub running: Running,
    pub paths: Vec<PathReport>,
    pub skipped: Vec<SkippedPath>,
    pub advice: Advice,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stages(f: impl FnOnce(&mut Stages)) -> Stages {
        let mut s = Stages {
            dns: true,
            tcp: true,
            tls: TlsStage::Done,
            status: Some(200),
            first_byte_ms: Some(120),
            bytes: 64 * 1024,
            complete: true,
            read_ms: 500,
            stalled: false,
        };
        f(&mut s);
        s
    }

    #[test]
    fn target_strips_scheme_path_login_and_port() {
        let t = Target::try_from(" https://User:pw@Example.com:443/a/b?x=1 ").unwrap();
        assert_eq!(t.host(), "example.com");
        assert_eq!(
            Target::try_from("example.com").unwrap().host(),
            "example.com"
        );
        assert_eq!(Target::try_from("8.8.8.8").unwrap().host(), "8.8.8.8");
    }

    #[test]
    fn target_rejects_bad_and_local_input() {
        for bad in [
            "",
            "  ",
            "не сайт",
            "exa_mple",
            "1.2.3",
            "[::1]:443",
            "localhost",
            "a.localhost",
        ] {
            assert!(!Target::try_from(bad).is_ok(), "принял «{bad}»");
        }
        for local in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
        ] {
            assert!(!Target::try_from(local).is_ok(), "принял «{local}»");
        }
    }

    #[test]
    fn verdict_follows_the_first_failed_stage() {
        assert_eq!(classify(&stages(|s| s.dns = false)), Verdict::NoAddress);
        assert_eq!(classify(&stages(|s| s.tcp = false)), Verdict::Unreachable);
        assert_eq!(
            classify(&stages(|s| s.tls = TlsStage::Skipped)),
            Verdict::Unreachable
        );
        assert_eq!(
            classify(&stages(|s| s.tls = TlsStage::Cut)),
            Verdict::TlsCut
        );
        assert_eq!(
            classify(&stages(|s| s.tls = TlsStage::Frozen)),
            Verdict::TlsFrozen
        );
        assert_eq!(
            classify(&stages(|s| s.status = Some(403))),
            Verdict::Refused
        );
        assert_eq!(
            classify(&stages(|s| s.status = Some(451))),
            Verdict::Refused
        );
        assert_eq!(classify(&stages(|_| {})), Verdict::Works);
    }

    #[test]
    fn stalled_stream_is_data_freeze_or_slow_answer() {
        // Поток замер, не дойдя до конца, — данные не идут.
        let frozen = stages(|s| {
            s.bytes = 16 * 1024;
            s.complete = false;
            s.stalled = true;
        });
        assert_eq!(classify(&frozen), Verdict::DataFrozen);
        // Замолчал до ответа — то же самое: соединение есть, данных нет.
        let silent = stages(|s| {
            s.status = None;
            s.first_byte_ms = None;
            s.stalled = true;
        });
        assert_eq!(classify(&silent), Verdict::DataFrozen);
        // Оборвали сразу после рукопожатия, ответа не дав, — режут по имени.
        let aborted = stages(|s| {
            s.status = None;
            s.first_byte_ms = None;
        });
        assert_eq!(classify(&aborted), Verdict::TlsCut);
        // Короткий ответ дочитан до конца — работает, какой бы ни была пауза.
        let short = stages(|s| s.bytes = 2 * 1024);
        assert_eq!(classify(&short), Verdict::Works);
    }

    #[test]
    fn slow_answer_is_not_a_cut() {
        let slow_start = stages(|s| s.first_byte_ms = Some(4_000));
        assert_eq!(classify(&slow_start), Verdict::Slow);
        let slow_read = stages(|s| s.read_ms = 4_000);
        assert_eq!(classify(&slow_read), Verdict::Slow);
    }

    #[test]
    fn kill_switch_leaves_only_the_tunnel() {
        let (probe, skipped) = plan_paths(Running::Vpn, true);
        assert_eq!(probe, vec![Path::Tunnel]);
        assert_eq!(skipped, vec![(Path::Direct, SkipReason::KillSwitch)]);

        let (probe, skipped) = plan_paths(Running::Hybrid, false);
        assert_eq!(probe, vec![Path::Tunnel, Path::Direct]);
        assert!(skipped.is_empty());

        let (probe, skipped) = plan_paths(Running::Zapret, true);
        assert_eq!(probe, vec![Path::Direct]);
        assert!(skipped.is_empty());

        let (probe, _) = plan_paths(Running::Off, false);
        assert_eq!(probe, vec![Path::Direct]);
    }

    #[test]
    fn advice_follows_the_worst_case() {
        let ok = &[(Path::Direct, Verdict::Works)];
        assert_eq!(conclude(Running::Off, ok), Advice::Works);
        assert_eq!(
            conclude(Running::Off, &[(Path::Direct, Verdict::TlsCut)]),
            Advice::TryVpn
        );
        assert_eq!(
            conclude(Running::Zapret, &[(Path::Direct, Verdict::DataFrozen)]),
            Advice::TryVpn
        );
        assert_eq!(
            conclude(Running::Off, &[(Path::Direct, Verdict::NoAddress)]),
            Advice::CheckDns
        );
        assert_eq!(
            conclude(
                Running::Vpn,
                &[
                    (Path::Tunnel, Verdict::TlsCut),
                    (Path::Direct, Verdict::TlsCut)
                ]
            ),
            Advice::StillCut
        );
        assert_eq!(
            conclude(
                Running::Vpn,
                &[
                    (Path::Tunnel, Verdict::Refused),
                    (Path::Direct, Verdict::Works)
                ]
            ),
            Advice::Works
        );
        assert_eq!(
            conclude(Running::Vpn, &[(Path::Tunnel, Verdict::Refused)]),
            Advice::ChangeServer
        );
    }
}
