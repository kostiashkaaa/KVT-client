//! NetGovernor — единственная точка, через которую приложение открывает новые
//! TLS-соединения (проверки серверов, подписки, обновления).
//!
//! По наблюдениям 2026 года ТСПУ замораживает узел, если к одному SNI за короткое
//! время открывается больше ~3 TLS-соединений. Поэтому диспетчер держит
//! счётчик на каждый SNI, выдерживает паузы и не даёт повторять попытки, пока
//! узел заморожен (повторы только продлевают блок).
//!
//! Пороги — данные (`presets/net-policy.json`, сверяется с `NetPolicy::default`
//! тестом) и меняются с выпуском KVT, без правки кода.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetPolicy {
    /// Сколько новых TLS-соединений к одному SNI разрешено за окно.
    pub max_new_tls_per_sni: usize,
    #[serde(with = "secs")]
    pub window: Duration,
    /// Минимальная пауза между соединениями к одному SNI.
    #[serde(with = "secs")]
    pub min_spacing: Duration,
    /// Сколько ждать после обнаруженной заморозки, прежде чем снова трогать SNI.
    #[serde(with = "secs")]
    pub freeze_cooldown: Duration,
    /// Сколько проверок серверов идёт одновременно (по разным SNI).
    pub max_parallel_probes: usize,
    /// Лимит новых соединений считать отдельно для каждого адреса сервера с этим
    /// SNI, а не на весь SNI. У REALITY десятки серверов провайдера часто
    /// маскируются под один сайт — с общим лимитом они проверяются по два в минуту.
    /// Заморозка в любом случае закрывает весь SNI.
    pub per_endpoint: bool,
}

impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            max_new_tls_per_sni: 2,
            window: Duration::from_secs(60),
            min_spacing: Duration::from_secs(2),
            freeze_cooldown: Duration::from_secs(180),
            max_parallel_probes: 4,
            per_endpoint: true,
        }
    }
}

mod secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_secs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Можно открывать соединение прямо сейчас; оно уже учтено.
    Allowed,
    /// Лимит исчерпан — повторить не раньше указанного момента.
    RetryAt(Instant),
    /// SNI заморожен: никаких попыток до указанного момента, отпечаток не менять.
    Frozen { until: Instant },
}

#[derive(Debug, Default)]
struct SniState {
    recent: VecDeque<Instant>,
    frozen_until: Option<Instant>,
}

/// Время передаётся снаружи (`now`), поэтому логика детерминирована и
/// проверяется тестами без реальных задержек.
#[derive(Debug, Default)]
pub struct NetGovernor {
    policy: NetPolicy,
    per_sni: HashMap<String, SniState>,
}

impl NetGovernor {
    pub fn new(policy: NetPolicy) -> Self {
        Self {
            policy,
            per_sni: HashMap::new(),
        }
    }

    pub fn policy(&self) -> &NetPolicy {
        &self.policy
    }

    pub fn try_acquire(&mut self, sni: &str, now: Instant) -> Decision {
        self.try_acquire_endpoint(sni, None, now)
    }

    /// Соединение к серверу `endpoint` (адрес из ссылки) с этим SNI. С
    /// `per_endpoint` лимит считается на пару SNI и адрес, заморозка — на весь SNI.
    pub fn try_acquire_endpoint(
        &mut self,
        sni: &str,
        endpoint: Option<&str>,
        now: Instant,
    ) -> Decision {
        let sni = sni.to_ascii_lowercase();
        if let Some(state) = self.per_sni.get_mut(&sni) {
            if let Some(until) = state.frozen_until {
                if now < until {
                    return Decision::Frozen { until };
                }
                state.frozen_until = None;
            }
        }
        let key = match endpoint.filter(|_| self.policy.per_endpoint) {
            // `|` не встречается ни в имени хоста, ни в адресе.
            Some(e) => format!("{sni}|{}", e.to_ascii_lowercase()),
            None => sni,
        };
        let policy = &self.policy;
        let state = self.per_sni.entry(key).or_default();

        while state
            .recent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= policy.window)
        {
            state.recent.pop_front();
        }

        if let Some(last) = state.recent.back() {
            let next = *last + policy.min_spacing;
            if now < next {
                return Decision::RetryAt(next);
            }
        }
        if state.recent.len() >= policy.max_new_tls_per_sni {
            if let Some(first) = state.recent.front() {
                return Decision::RetryAt(*first + policy.window);
            }
        }

        state.recent.push_back(now);
        Decision::Allowed
    }

    /// Проба увидела признаки заморозки (TCP есть, ответа на ClientHello нет,
    /// или поток встал после ~16 КБ).
    pub fn report_freeze(&mut self, sni: &str, now: Instant) {
        let state = self.per_sni.entry(sni.to_ascii_lowercase()).or_default();
        state.frozen_until = Some(now + self.policy.freeze_cooldown);
    }

    pub fn frozen_until(&self, sni: &str, now: Instant) -> Option<Instant> {
        self.per_sni
            .get(&sni.to_ascii_lowercase())
            .and_then(|s| s.frozen_until)
            .filter(|until| now < *until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn gov() -> (NetGovernor, Instant) {
        (NetGovernor::new(NetPolicy::default()), Instant::now())
    }

    #[test]
    fn spacing_is_enforced() {
        let (mut g, t0) = gov();
        assert_eq!(g.try_acquire("www.microsoft.com", t0), Decision::Allowed);
        assert_eq!(
            g.try_acquire("www.microsoft.com", t0 + Duration::from_millis(500)),
            Decision::RetryAt(t0 + Duration::from_secs(2))
        );
        // Другой SNI не зависит от первого.
        assert_eq!(g.try_acquire("cdn.example.com", t0), Decision::Allowed);
    }

    #[test]
    fn window_limit_is_enforced() {
        let (mut g, t0) = gov();
        assert_eq!(g.try_acquire("a.com", t0), Decision::Allowed);
        assert_eq!(
            g.try_acquire("a.com", t0 + Duration::from_secs(3)),
            Decision::Allowed
        );
        assert_eq!(
            g.try_acquire("a.com", t0 + Duration::from_secs(10)),
            Decision::RetryAt(t0 + Duration::from_secs(60))
        );
        assert_eq!(
            g.try_acquire("a.com", t0 + Duration::from_secs(60)),
            Decision::Allowed
        );
    }

    #[test]
    fn preset_file_matches_defaults() {
        let from_file: NetPolicy =
            serde_json::from_str(include_str!("../../../presets/net-policy.json")).unwrap();
        assert_eq!(from_file, NetPolicy::default());
    }

    #[test]
    fn sni_is_case_insensitive() {
        let (mut g, t0) = gov();
        assert_eq!(g.try_acquire("A.com", t0), Decision::Allowed);
        assert!(matches!(g.try_acquire("a.COM", t0), Decision::RetryAt(_)));
    }

    #[test]
    fn per_endpoint_limits_each_server_but_freezes_whole_sni() {
        let t0 = Instant::now();
        let mut g = NetGovernor::new(NetPolicy {
            per_endpoint: true,
            ..NetPolicy::default()
        });
        let sni = "www.microsoft.com";
        assert_eq!(
            g.try_acquire_endpoint(sni, Some("203.0.113.1"), t0),
            Decision::Allowed
        );
        // Другой сервер с тем же SNI — свой лимит.
        assert_eq!(
            g.try_acquire_endpoint(sni, Some("203.0.113.2"), t0),
            Decision::Allowed
        );
        // Тот же сервер — пауза, как раньше.
        assert!(matches!(
            g.try_acquire_endpoint(sni, Some("203.0.113.1"), t0),
            Decision::RetryAt(_)
        ));
        g.report_freeze(sni, t0);
        assert!(matches!(
            g.try_acquire_endpoint(sni, Some("203.0.113.9"), t0),
            Decision::Frozen { .. }
        ));
        assert!(matches!(g.try_acquire(sni, t0), Decision::Frozen { .. }));

        // Без `per_endpoint` адрес не важен — общий лимит на SNI.
        let mut g = NetGovernor::new(NetPolicy {
            per_endpoint: false,
            ..NetPolicy::default()
        });
        assert_eq!(
            g.try_acquire_endpoint(sni, Some("203.0.113.1"), t0),
            Decision::Allowed
        );
        assert!(matches!(
            g.try_acquire_endpoint(sni, Some("203.0.113.2"), t0),
            Decision::RetryAt(_)
        ));
    }

    #[test]
    fn freeze_blocks_all_attempts_until_cooldown() {
        let (mut g, t0) = gov();
        g.report_freeze("a.com", t0);
        let until = t0 + Duration::from_secs(180);
        assert_eq!(
            g.try_acquire("a.com", t0 + Duration::from_secs(179)),
            Decision::Frozen { until }
        );
        assert_eq!(g.frozen_until("a.com", t0), Some(until));
        assert_eq!(g.try_acquire("a.com", until), Decision::Allowed);
        assert_eq!(g.frozen_until("a.com", until), None);
    }

    proptest! {
        /// Инвариант: при любом расписании запросов к одному SNI разрешённые
        /// соединения не превышают лимит окна и не идут чаще min_spacing.
        #[test]
        fn never_exceeds_policy(deltas in proptest::collection::vec(0u64..5_000, 1..200)) {
            let policy = NetPolicy::default();
            let mut g = NetGovernor::new(policy.clone());
            let t0 = Instant::now();
            let mut now = t0;
            let mut allowed: Vec<Instant> = Vec::new();
            for d in deltas {
                now += Duration::from_millis(d);
                if g.try_acquire("x.com", now) == Decision::Allowed {
                    allowed.push(now);
                }
            }
            for pair in allowed.windows(2) {
                prop_assert!(pair[1] - pair[0] >= policy.min_spacing);
            }
            for (i, start) in allowed.iter().enumerate() {
                let in_window = allowed[i..].iter().take_while(|t| **t - *start < policy.window).count();
                prop_assert!(in_window <= policy.max_new_tls_per_sni);
            }
        }
    }
}
