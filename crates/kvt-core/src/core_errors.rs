//! Ошибки ядер как данные. Строки журнала Xray и sing-box сопоставляются с
//! правилами из `presets/core-errors.json`: у правила есть код, понятный текст и
//! действие. Новый случай добавляется правкой файла, без изменения кода.

use crate::core_select::CoreKind;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const RULES_JSON: &str = include_str!("../../../presets/core-errors.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Только записать в журнал.
    Log,
    /// Остановить подключение и показать текст.
    Stop,
    /// Один раз переподключиться.
    Reconnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Rule {
    pub code: String,
    /// Для каких ядер (`xray`, `sing-box`); пусто — для всех.
    #[serde(default)]
    pub cores: Vec<String>,
    /// Подстроки в нижнем регистре; достаточно одной.
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    pub text: String,
    pub action: Action,
    /// Сколько совпадений за окно нужно для действия.
    #[serde(default = "one")]
    pub count: usize,
    /// Окно в секундах.
    #[serde(default = "minute")]
    pub window: u64,
}

fn one() -> usize {
    1
}

fn minute() -> u64 {
    60
}

#[derive(Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

fn core_name(core: CoreKind) -> &'static str {
    match core {
        CoreKind::Xray => "xray",
        CoreKind::SingBox => "sing-box",
    }
}

impl Rule {
    fn applies(&self, core: CoreKind, lower: &str) -> bool {
        (self.cores.is_empty() || self.cores.iter().any(|c| c == core_name(core)))
            && self.patterns.iter().any(|p| lower.contains(p.as_str()))
    }
}

/// Правила из файла данных (разбираются один раз).
pub fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| parse(RULES_JSON).unwrap_or_default())
}

fn parse(json: &str) -> Result<Vec<Rule>, serde_json::Error> {
    let file: RulesFile = serde_json::from_str(json)?;
    Ok(file
        .rules
        .into_iter()
        .map(|mut r| {
            r.patterns = r.patterns.iter().map(|p| p.to_lowercase()).collect();
            r
        })
        .collect())
}

/// Первое правило, под которое подходит строка журнала.
pub fn classify(core: CoreKind, line: &str) -> Option<&'static Rule> {
    let lower = line.to_lowercase();
    rules().iter().find(|r| r.applies(core, &lower))
}

/// Сработавшее правило: строк набралось столько, сколько оно требует.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triggered {
    pub code: String,
    pub text: String,
    pub action: Action,
}

/// Считает совпадения по кодам за скользящее окно.
#[derive(Debug, Default)]
pub struct Watcher {
    seen: HashMap<String, VecDeque<Instant>>,
}

impl Watcher {
    /// Учитывает строку; возвращает правило, если по нему пора действовать.
    /// После срабатывания счётчик кода сбрасывается.
    pub fn observe(&mut self, core: CoreKind, line: &str, now: Instant) -> Option<Triggered> {
        let rule = classify(core, line)?;
        self.observe_rule(rule, now)
    }

    fn observe_rule(&mut self, rule: &Rule, now: Instant) -> Option<Triggered> {
        let window = Duration::from_secs(rule.window);
        let times = self.seen.entry(rule.code.clone()).or_default();
        times.push_back(now);
        while times
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > window)
        {
            times.pop_front();
        }
        if times.len() < rule.count.max(1) {
            return None;
        }
        times.clear();
        Some(Triggered {
            code: rule.code.clone(),
            text: rule.text.clone(),
            action: rule.action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_file_is_valid() {
        let rules = parse(RULES_JSON).unwrap();
        assert!(rules.len() >= 6);
        for r in &rules {
            assert!(!r.patterns.is_empty(), "{}", r.code);
            assert!(!r.text.is_empty(), "{}", r.code);
            assert!(r.count >= 1, "{}", r.code);
            for c in &r.cores {
                assert!(c == "xray" || c == "sing-box", "{}: {c}", r.code);
            }
        }
        let mut codes: Vec<_> = rules.iter().map(|r| &r.code).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), rules.len(), "коды правил повторяются");
    }

    #[test]
    fn typical_lines() {
        let line = "2026/11/04 12:00:01 [Warning] failed to dial > REALITY: received real certificate (potential MITM or redirection)";
        assert_eq!(
            classify(CoreKind::Xray, line).unwrap().code,
            "reality_mismatch"
        );
        // Правило только для Xray не срабатывает на sing-box.
        assert!(
            classify(CoreKind::SingBox, "REALITY: received real certificate")
                .map_or(true, |r| r.code != "reality_mismatch")
        );
        let line = "ERROR outbound/vless[proxy]: tls: failed to verify certificate: x509: certificate has expired";
        assert_eq!(
            classify(CoreKind::SingBox, line).unwrap().code,
            "bad_certificate"
        );
        let line = "WARN dial tcp [сервер]:443: i/o timeout";
        assert_eq!(
            classify(CoreKind::SingBox, line).unwrap().action,
            Action::Log
        );
        assert!(classify(CoreKind::Xray, "Xray 25.1.1 started").is_none());
        // Windows не дала настроить адаптер (у пользователя был отключён IPv6).
        // Попытки Xray — повод переподключиться без IPv6, а не остановиться.
        let line = "2026/11/07 16:43:49.087028 [Error] proxy/tun: Interface configuration failed, retrying attempt 1/15 > proxy/tun: unable to set routes > Element not found.";
        let rule = classify(CoreKind::Xray, line).unwrap();
        assert_eq!(rule.code, "tun_ipv6");
        assert_eq!(rule.action, Action::Reconnect);
        let line =
            "Failed to start: app/proxyman/inbound: failed to start proxy > Element not found.";
        assert_eq!(
            classify(CoreKind::Xray, line).unwrap().code,
            "tun_not_configured"
        );
        // sing-box сразу выходит с этой строкой — служба переподключит без IPv6.
        let line = "FATAL start service: start inbound/tun[tun-in]: configure tun interface: Element not found.";
        assert_eq!(classify(CoreKind::SingBox, line).unwrap().code, "tun_ipv6");
        // Оставшееся устройство Wintun у обоих ядер — переподключение.
        for (core, line) in [
            (CoreKind::Xray, "Failed to start: app/proxyman/inbound: failed to start proxy > Cannot create a file when that file already exists."),
            (CoreKind::SingBox, "FATAL start service: start inbound/tun[tun-in]: create adapter: Cannot create a file when that file already exists."),
        ] {
            let rule = classify(core, line).unwrap();
            assert_eq!((rule.code.as_str(), rule.action), ("tun_busy", Action::Reconnect), "{line}");
        }
    }

    /// Обычный запуск Xray с Wintun. «Элемент не найден» здесь — адаптера KVT ещё нет,
    /// и он создаётся; правило на эту подстроку останавливало каждое подключение
    /// (тестовая 0.9.4, 2026-11-07). Язык строки — язык Windows.
    #[test]
    fn normal_startup_lines_are_not_errors() {
        for line in [
            "Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 windows/amd64)",
            "A unified platform for anti-censorship.",
            "2026/11/07 16:43:48.730741 [Info] infra/conf/serial: Reading config: &{Name:C:\\ProgramData\\KVT\\run\\xray.json Format:json}",
            "2026/11/07 16:43:48.816662 Failed to find matching adapter name: Элемент не найден. (Code 0x00000490)",
            "2026/11/07 16:43:48.816662 Failed to find matching adapter name: Element not found. (Code 0x00000490)",
            "2026/11/07 16:43:48.888187 Using existing driver 0.14",
            "2026/11/07 16:43:48.900737 Creating adapter",
            "2026/11/07 16:43:49.135330 from DNS accepted udp:77.88.8.8:53 [xray.system -> direct]",
        ] {
            assert!(
                classify(CoreKind::Xray, line).map_or(true, |r| r.action == Action::Log),
                "{line}"
            );
        }
    }

    /// Обрыв соединения через туннель — частое и обычно безобидное событие (закрыли
    /// вкладку, перезапустили программу). Переподключать VPN из-за него нельзя:
    /// второе срабатывание останавливало подключение, и kill switch закрывал интернет.
    #[test]
    fn connection_resets_never_touch_the_connection() {
        for line in [
            "2026/11/06 20:15:39 [Warning] [1] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: connection ends > wsarecv: Удаленный хост принудительно разорвал существующее подключение.",
            "[Warning] failed to transfer response payload > readfrom tcp: wsarecv: An established connection was aborted by the software in your host machine.",
            "ERROR connection: read: connection reset by peer",
        ] {
            for core in [CoreKind::Xray, CoreKind::SingBox] {
                assert_eq!(classify(core, line).unwrap().action, Action::Log, "{line}");
            }
        }
    }

    #[test]
    fn action_after_count_within_window() {
        let rule = Rule {
            code: "x".into(),
            cores: vec![],
            patterns: vec!["boom".into()],
            text: "t".into(),
            action: Action::Stop,
            count: 3,
            window: 60,
        };
        let mut w = Watcher::default();
        let t0 = Instant::now();
        assert!(w.observe_rule(&rule, t0).is_none());
        // Старое совпадение выпало из окна.
        assert!(w
            .observe_rule(&rule, t0 + Duration::from_secs(61))
            .is_none());
        assert!(w
            .observe_rule(&rule, t0 + Duration::from_secs(62))
            .is_none());
        let hit = w.observe_rule(&rule, t0 + Duration::from_secs(63)).unwrap();
        assert_eq!(hit.action, Action::Stop);
        // После срабатывания счёт начинается заново.
        assert!(w
            .observe_rule(&rule, t0 + Duration::from_secs(64))
            .is_none());
    }
}
