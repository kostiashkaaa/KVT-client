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
