//! Данные мини-панели: выбор, переключатели, серверы с последним известным пингом и
//! подписка выбранного сервера. Только то, что показывается: адресов, портов и ключей
//! доступа здесь нет (как в `ServerSummary`).
//!
//! Статус, сеанс и плитки сервисов панель берёт теми же командами, что и окно.

use super::*;
use kvt_core::probe::Verdict;
use kvt_core::tester::QuickResult;
use serde::Serialize;

/// Серверов в списке панели; выбранный попадает в него всегда.
const SERVERS_IN_PANEL: usize = 30;

/// Что известно о проверке сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Health {
    Works,
    Slow,
    Down,
    Unknown,
}

/// Проверка сервера и пинг, которые у нас есть. Вердикт — из полной проверки или из
/// проверки туннеля; задержка — TCP-пинг окна, а без него — время той проверки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    health: Health,
    ping_ms: Option<u64>,
}

impl Known {
    fn of(outcome: Option<&Outcome>, ping: Option<&QuickResult>) -> Self {
        let tcp = match ping {
            Some(QuickResult::Reachable { latency_ms }) => Some(*latency_ms),
            _ => None,
        };
        match outcome {
            Some(Outcome::Checked {
                verdict: verdict @ (Verdict::Works | Verdict::Slow),
                latency_ms,
            }) => Self {
                health: if *verdict == Verdict::Works {
                    Health::Works
                } else {
                    Health::Slow
                },
                ping_ms: tcp.or(*latency_ms),
            },
            Some(Outcome::Checked { .. }) => Self {
                health: Health::Down,
                ping_ms: None,
            },
            // Полной проверки не было: TCP-порт не отвечает — скорее всего, заблокирован,
            // отвечает — это ещё не «работает» (заморозка по TLS пинг не видит).
            _ => Self {
                health: match ping {
                    Some(QuickResult::Unreachable | QuickResult::DnsFailed) => Health::Down,
                    _ => Health::Unknown,
                },
                ping_ms: tcp,
            },
        }
    }

    /// Порядок в списке: проверенные рабочие по задержке, затем не проверенные с пингом
    /// по задержке, затем без пинга, затем неработающие.
    fn rank(self) -> (u8, u64) {
        match (self.health, self.ping_ms) {
            (Health::Works | Health::Slow, ms) => (0, ms.unwrap_or(u64::MAX)),
            (Health::Unknown, Some(ms)) => (1, ms),
            (Health::Unknown, None) => (2, 0),
            (Health::Down, _) => (3, 0),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PanelServer {
    key: String,
    name: String,
    /// Страна по первому флагу в названии (`nl`).
    flag: Option<String>,
    protocol: &'static str,
    transport: &'static str,
    security: &'static str,
    /// Последняя известная задержка, мс (пинги панель сама не снимает).
    ping_ms: Option<u64>,
    health: Health,
}

impl PanelServer {
    fn new(s: &crate::ServerSummary, known: Known) -> Self {
        Self {
            key: s.key.clone(),
            name: s.name.clone(),
            flag: s.flag.clone(),
            protocol: s.protocol,
            transport: s.transport,
            security: s.security,
            ping_ms: known.ping_ms,
            health: known.health,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PanelZapret {
    /// Название стратегии, как в окне («Основная», «ALT4»).
    strategy: String,
    /// Сеть, для которой стратегию подобрал автоподбор; `None` — выбрана вручную или
    /// основная.
    picked_for: Option<String>,
}

/// Подписка выбранного сервера: остаток трафика и срок.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PanelSubscription {
    title: String,
    used_bytes: Option<u64>,
    total_bytes: Option<u64>,
    /// Unix-время окончания.
    expire: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PanelView {
    /// `vpn`, `hybrid` или `zapret`.
    mode: String,
    kill_switch: bool,
    auto_switch: bool,
    /// Прокси для Telegram Desktop.
    telegram: bool,
    server: Option<PanelServer>,
    /// Проверенные рабочие по задержке, затем остальные (см. `Known::rank`).
    servers: Vec<PanelServer>,
    /// Серверов в подписках всего: больше, чем в списке, — есть «Все серверы в окне».
    total: usize,
    zapret: PanelZapret,
    subscription: Option<PanelSubscription>,
}

/// Собирает вид панели из выбора, подписок, итогов проверок и пингов. Без обращений к
/// состоянию приложения, чтобы порядок и состав проверяли тесты.
pub(super) fn build(
    choice: &crate::Choice,
    groups: &[crate::catalog::Group],
    outcomes: &HashMap<String, Outcome>,
    pings: &HashMap<String, QuickResult>,
    network: Option<&crate::netinfo::Network>,
) -> PanelView {
    let selected = choice.server.as_deref();
    let all: Vec<&crate::ServerSummary> = groups.iter().flat_map(|g| g.servers.iter()).collect();
    let known = |s: &crate::ServerSummary| Known::of(outcomes.get(&s.key), pings.get(&s.key));

    let server = all
        .iter()
        .find(|s| Some(s.key.as_str()) == selected)
        .map(|s| PanelServer::new(s, known(s)));

    // Порядок считаем по ссылкам, а `PanelServer` строим только для попавших в список:
    // серверов в подписках бывает десятки тысяч.
    let mut ranked: Vec<(usize, Known)> =
        all.iter().enumerate().map(|(i, s)| (i, known(s))).collect();
    ranked.sort_by_key(|&(i, k)| (k.rank(), i));
    let mut picked: Vec<usize> = ranked
        .iter()
        .take(SERVERS_IN_PANEL)
        .map(|&(i, _)| i)
        .collect();
    if let Some(i) = all
        .iter()
        .position(|s| Some(s.key.as_str()) == selected)
        .filter(|i| !picked.contains(i))
    {
        picked.push(i);
    }
    let servers = picked
        .into_iter()
        .filter_map(|i| all.get(i).map(|s| PanelServer::new(s, known(s))))
        .collect();

    let subscription = selected
        .and_then(|key| {
            groups
                .iter()
                .find(|g| g.servers.iter().any(|s| s.key == key))
        })
        .and_then(|g| {
            let m = &g.meta;
            (m.total_bytes.is_some() || m.expire.is_some()).then(|| PanelSubscription {
                title: m.title.clone().unwrap_or_else(|| g.title.clone()),
                used_bytes: m.used_bytes,
                total_bytes: m.total_bytes,
                expire: m.expire,
            })
        });
    let picked_for = network
        .filter(|n| choice.zapret.by_network.contains_key(&n.key))
        .map(|n| n.label.clone());
    PanelView {
        mode: choice.mode.clone().unwrap_or_else(|| "vpn".into()),
        kill_switch: choice.kill_switch,
        auto_switch: choice.auto_switch,
        telegram: choice.zapret.telegram,
        server,
        servers,
        total: all.len(),
        zapret: PanelZapret {
            strategy: strategy_title(&choice.zapret.strategy_for(network.map(|n| n.key.as_str()))),
            picked_for,
        },
        subscription,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netinfo::{NetKind, Network};

    fn server(key: &str, name: &str) -> crate::ServerSummary {
        crate::ServerSummary {
            key: key.into(),
            name: name.into(),
            flag: Some("nl".into()),
            protocol: "vless",
            transport: "tcp",
            security: "reality",
            core: kvt_core::core_select::CoreKind::Xray,
            same_as: None,
        }
    }

    fn group(
        id: &str,
        servers: Vec<crate::ServerSummary>,
        meta: crate::SubscriptionInfo,
    ) -> crate::catalog::Group {
        crate::catalog::Group {
            id: id.into(),
            title: format!("Подписка {id}"),
            by_url: true,
            updated_at: 0,
            meta,
            servers,
            info: Vec::new(),
            errors: 0,
        }
    }

    fn no_meta() -> crate::SubscriptionInfo {
        crate::SubscriptionInfo {
            title: None,
            used_bytes: None,
            total_bytes: None,
            expire: None,
            support_url: None,
            announce: None,
        }
    }

    fn works(ms: u64) -> Outcome {
        Outcome::Checked {
            verdict: Verdict::Works,
            latency_ms: Some(ms),
        }
    }

    fn pinged(ms: u64) -> QuickResult {
        QuickResult::Reachable { latency_ms: ms }
    }

    fn build_simple(
        choice: &crate::Choice,
        groups: &[crate::catalog::Group],
        outcomes: &HashMap<String, Outcome>,
        pings: &HashMap<String, QuickResult>,
    ) -> PanelView {
        build(choice, groups, outcomes, pings, None)
    }

    fn keys(view: &PanelView) -> Vec<&str> {
        view.servers.iter().map(|s| s.key.as_str()).collect()
    }

    #[test]
    fn checked_servers_come_first_then_pinged_then_the_rest_then_broken() {
        let groups = [group(
            "a",
            vec![
                server("a", "A"),
                server("b", "B"),
                server("c", "C"),
                server("d", "D"),
                server("e", "E"),
                server("f", "F"),
            ],
            no_meta(),
        )];
        let outcomes = HashMap::from([
            ("a".to_owned(), works(90)),
            ("b".to_owned(), works(40)),
            (
                "d".to_owned(),
                Outcome::Checked {
                    verdict: Verdict::Unreachable,
                    latency_ms: None,
                },
            ),
        ]);
        let pings = HashMap::from([
            ("e".to_owned(), pinged(70)),
            ("f".to_owned(), pinged(20)),
            ("c".to_owned(), QuickResult::NotApplicable),
        ]);
        let choice = crate::Choice {
            server: Some("a".into()),
            ..Default::default()
        };
        let view = build_simple(&choice, &groups, &outcomes, &pings);
        // Проверенные b (40), a (90); не проверенные с пингом f (20), e (70); без пинга c;
        // неработающий d.
        assert_eq!(keys(&view), ["b", "a", "f", "e", "c", "d"]);
        assert_eq!(view.servers[2].health, Health::Unknown);
        assert_eq!(view.servers[2].ping_ms, Some(20));
        assert_eq!(view.servers[5].health, Health::Down);
        assert_eq!(view.server.as_ref().map(|s| s.key.as_str()), Some("a"));
        assert_eq!(view.total, 6);
    }

    #[test]
    fn tcp_ping_is_shown_but_the_verdict_comes_from_the_check() {
        let groups = [group("a", vec![server("a", "A")], no_meta())];
        let outcomes = HashMap::from([("a".to_owned(), works(300))]);
        let pings = HashMap::from([("a".to_owned(), pinged(38))]);
        let view = build_simple(&crate::Choice::default(), &groups, &outcomes, &pings);
        assert_eq!(view.servers[0].health, Health::Works);
        // Пинг сравним между серверами, а время проверки туннеля — нет.
        assert_eq!(view.servers[0].ping_ms, Some(38));
    }

    #[test]
    fn a_closed_port_without_a_full_check_is_down() {
        let groups = [group(
            "a",
            vec![server("a", "A"), server("b", "B")],
            no_meta(),
        )];
        let pings = HashMap::from([
            ("a".to_owned(), QuickResult::Unreachable),
            ("b".to_owned(), QuickResult::DnsFailed),
        ]);
        let view = build_simple(&crate::Choice::default(), &groups, &HashMap::new(), &pings);
        assert!(view.servers.iter().all(|s| s.health == Health::Down));
        assert!(view.servers.iter().all(|s| s.ping_ms.is_none()));
    }

    #[test]
    fn a_long_list_is_cut_but_the_selected_server_stays() {
        let servers: Vec<_> = (0..100).map(|i| server(&format!("s{i}"), "S")).collect();
        let groups = [group("a", servers, no_meta())];
        let choice = crate::Choice {
            server: Some("s99".into()),
            ..Default::default()
        };
        let view = build_simple(&choice, &groups, &HashMap::new(), &HashMap::new());
        assert_eq!(view.servers.len(), SERVERS_IN_PANEL + 1);
        assert!(view.servers.iter().any(|s| s.key == "s99"));
        assert_eq!(view.total, 100);
    }

    #[test]
    fn subscription_is_the_one_of_the_selected_server() {
        let with_traffic = crate::SubscriptionInfo {
            title: Some("Мой VPN".into()),
            used_bytes: Some(34),
            total_bytes: Some(200),
            expire: Some(1_800_000_000),
            ..no_meta()
        };
        let groups = [
            group("a", vec![server("a1", "A1")], no_meta()),
            group("b", vec![server("b1", "B1")], with_traffic),
        ];
        let pick = |key: &str| crate::Choice {
            server: Some(key.into()),
            ..Default::default()
        };
        let none = HashMap::new();
        let pings = HashMap::new();
        assert!(build_simple(&pick("a1"), &groups, &none, &pings)
            .subscription
            .is_none());
        let sub = build_simple(&pick("b1"), &groups, &none, &pings)
            .subscription
            .expect("у подписки есть трафик и срок");
        assert_eq!(sub.title, "Мой VPN");
        assert_eq!((sub.used_bytes, sub.total_bytes), (Some(34), Some(200)));
    }

    #[test]
    fn zapret_row_says_which_network_the_strategy_was_picked_for() {
        let net = Network {
            key: "home".into(),
            label: "Home 5G".into(),
            kind: NetKind::Wifi,
            dns: Vec::new(),
        };
        let none = HashMap::new();
        let pings = HashMap::new();
        let mut choice = crate::Choice::default();
        let view = build(&choice, &[], &none, &pings, Some(&net));
        assert_eq!(view.zapret.picked_for, None);
        assert_eq!(view.zapret.strategy, "Основная");

        choice
            .zapret
            .by_network
            .insert("home".into(), "general (ALT4)".into());
        let view = build(&choice, &[], &none, &pings, Some(&net));
        assert_eq!(view.zapret.picked_for.as_deref(), Some("Home 5G"));
        assert_eq!(view.zapret.strategy, "ALT4");
        // Другая сеть — подбор для неё не делали.
        let other = Network {
            key: "work".into(),
            ..net
        };
        assert_eq!(
            build(&choice, &[], &none, &pings, Some(&other))
                .zapret
                .picked_for,
            None
        );
    }

    #[test]
    fn nothing_selected_is_fine() {
        let view = build_simple(
            &crate::Choice::default(),
            &[],
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(view.server.is_none());
        assert!(view.servers.is_empty());
        assert_eq!(view.mode, "vpn");
        assert!(view.telegram && view.auto_switch && !view.kill_switch);
    }
}
