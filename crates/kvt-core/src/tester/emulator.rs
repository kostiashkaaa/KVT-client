//! Эмулятор ТСПУ для тестов по наблюдениям сообщества (2026):
//! - больше 3 TLS-рукопожатий к одному SNI за 60 с → заморозка SNI на 120 с;
//! - к «помеченным» адресам поток замирает после 16 КБ.
//!
//! Как именно ТСПУ считает рукопожатия — по SNI вообще или по паре SNI и адрес
//! сервера, — не подтверждено. Эмулятор умеет оба варианта (`per_endpoint`), чтобы
//! тесты показали поведение планировщика в каждом.
//!
//! Считает нарушения, чтобы тесты могли доказать, что планировщик их не вызывает.

use super::Prober;
use crate::model::Server;
use crate::probe::ProbeObservation;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

const HANDSHAKE_LIMIT: usize = 3;
const WINDOW: Duration = Duration::from_secs(60);
const FREEZE: Duration = Duration::from_secs(120);
const RTT: Duration = Duration::from_millis(150);

#[derive(Default)]
struct State {
    handshakes: HashMap<String, VecDeque<Instant>>,
    frozen_until: HashMap<String, Instant>,
    violations: usize,
    attempts: usize,
}

#[derive(Default)]
pub struct TspuEmulator {
    flagged: HashSet<String>,
    /// Считать рукопожатия на пару SNI и адрес, а не на весь SNI.
    per_endpoint: bool,
    state: Mutex<State>,
}

impl TspuEmulator {
    pub fn with_flagged(mut self, address: &str) -> Self {
        self.flagged.insert(address.to_owned());
        self
    }

    pub fn per_endpoint(mut self) -> Self {
        self.per_endpoint = true;
        self
    }

    pub fn violations(&self) -> usize {
        self.state.lock().unwrap().violations
    }

    pub fn attempts(&self) -> usize {
        self.state.lock().unwrap().attempts
    }

    fn observe(&self, server: &Server) -> ProbeObservation {
        let sni = server
            .visible_sni()
            .unwrap_or(&server.address)
            .to_ascii_lowercase();
        let sni = if self.per_endpoint {
            format!("{sni}|{}", server.address)
        } else {
            sni
        };
        let now = Instant::now();
        let mut st = self.state.lock().unwrap();
        st.attempts += 1;

        let frozen = |obs: ProbeObservation| ProbeObservation {
            tls_handshake_done: false,
            ..obs
        };
        let base = ProbeObservation {
            dns_resolved: true,
            tcp_connected: true,
            tls_handshake_done: true,
            bytes_received: 200 * 1024,
            stalled: false,
            download_completed: true,
            latency: Some(RTT),
            core_error: false,
            rejected: false,
        };

        if st.frozen_until.get(&sni).is_some_and(|until| now < *until) {
            return frozen(base);
        }
        let list = st.handshakes.entry(sni.clone()).or_default();
        list.push_back(now);
        while list
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            list.pop_front();
        }
        if list.len() > HANDSHAKE_LIMIT {
            st.violations += 1;
            st.frozen_until.insert(sni, now + FREEZE);
            return frozen(base);
        }
        if self.flagged.contains(&server.address) {
            return ProbeObservation {
                bytes_received: 16 * 1024,
                stalled: true,
                download_completed: false,
                ..base
            };
        }
        base
    }
}

impl Prober for TspuEmulator {
    async fn probe(&self, server: Server) -> ProbeObservation {
        let obs = self.observe(&server);
        tokio::time::sleep(RTT).await;
        obs
    }
}
