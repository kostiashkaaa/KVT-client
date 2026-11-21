//! Тесты выводов «Почему не работает?» и текстов.

use super::*;
use crate::health::Trace;
use kvt_core::core_select::CoreKind;
use kvt_core::ipc::ServiceStatus;
use kvt_core::probe::Verdict;
use kvt_core::tester::QuickResult;

#[test]
fn english_texts() {
    use kvt_core::i18n::{with, Lang};
    let d = with(Lang::En, || {
        conclude(&Facts {
            network: false,
            ..base()
        })
    });
    assert_eq!(d.title, "The computer isn't connected to a network");
    assert_eq!(d.steps[0].title, "Network");
    let d = with(Lang::En, || {
        conclude(&Facts {
            server_tcp: Some(QuickResult::Unreachable),
            ..base()
        })
    });
    assert!(d.detail.contains("You can switch to “DE”"), "{}", d.detail);
}

/// Всё в порядке, ничего не подключено, у подписки есть замена серверу (`k3`, «DE»).
/// Общий для тестов выводов про сервис (`service`).
pub(super) fn base() -> Facts {
    Facts {
        network: true,
        service: Some(ServiceStatus::Disconnected),
        subscription: Some(SubFacts::default()),
        server: Some("NL".into()),
        server_tcp: Some(QuickResult::Reachable { latency_ms: 40 }),
        internet: Some(true),
        probe: Some(ProbeFact::Done(Verdict::Works)),
        tunnel: None,
        alternative: Some(("k3".into(), "DE".into())),
        captive: false,
        focus: None,
    }
}

#[test]
fn diagnose_picks_the_answer_by_focus() {
    // Без сервиса — общий вывод, с сервисом — про него.
    let mut f = base();
    assert_eq!(diagnose(&f), conclude(&f));
    f.focus = Some(ServiceFact {
        name: "Discord".into(),
        via: kvt_core::services::Via::Direct,
        health: kvt_core::services::Health::Down(kvt_core::services::Cause::Cut),
    });
    assert_eq!(diagnose(&f).title, "Discord не открывается");
}

#[test]
fn captive_portal_offers_disconnect_instead_of_another_server() {
    let mut f = base();
    f.service = Some(ServiceStatus::Connected {
        core: CoreKind::Xray,
    });
    f.probe = None;
    f.tunnel = Some(Err("нет ответа".into()));
    f.captive = true;
    let d = conclude(&f);
    assert_eq!(d.title, "Сеть просит войти");
    assert_eq!(d.fix, Some(Fix::Disconnect));
    assert_eq!(failing_step(&d), Some("Вход в сеть"));
    let mut titles: Vec<_> = d.steps.iter().map(|s| s.title).collect();
    titles.dedup();
    assert_eq!(titles.len(), d.steps.len(), "названия шагов повторяются");
}

fn failing_step(d: &Diagnosis) -> Option<&'static str> {
    d.steps
        .iter()
        .find(|s| s.state == StepState::Fail)
        .map(|s| s.title)
}

#[test]
fn working_server_offers_connect() {
    let d = conclude(&base());
    assert_eq!(d.tone, Tone::Ok);
    assert_eq!(d.fix, Some(Fix::Connect));
    assert_eq!(failing_step(&d), None);
}

#[test]
fn first_problem_wins() {
    let mut f = base();
    f.network = false;
    f.service = None;
    let d = conclude(&f);
    assert_eq!(d.title, "Компьютер не подключён к сети");
    assert_eq!(d.steps.len(), 1);

    let mut f = base();
    f.service = None;
    assert_eq!(failing_step(&conclude(&f)), Some("Служба KVT"));
}

#[test]
fn kill_switch_after_crash_offers_disconnect() {
    let mut f = base();
    f.service = Some(ServiceStatus::Failed {
        reason: "ядро остановилось".into(),
        blocked: true,
    });
    assert_eq!(conclude(&f).fix, Some(Fix::Disconnect));
}

#[test]
fn expired_subscription() {
    let mut f = base();
    f.subscription = Some(SubFacts {
        expired: true,
        exhausted: false,
    });
    let d = conclude(&f);
    assert_eq!(d.fix, Some(Fix::RefreshSubscription));
    assert_eq!(d.title, "Срок подписки закончился");
}

#[test]
fn no_internet_without_vpn_is_not_our_problem() {
    let mut f = base();
    f.internet = Some(false);
    let d = conclude(&f);
    assert_eq!(d.title, "Интернет не работает даже без VPN");
    assert_eq!(d.fix, None);
}

#[test]
fn unreachable_server_offers_alternative() {
    let mut f = base();
    f.server_tcp = Some(QuickResult::Unreachable);
    let d = conclude(&f);
    assert_eq!(
        d.fix,
        Some(Fix::SwitchServer {
            key: "k3".into(),
            name: "DE".into()
        })
    );
    assert!(d.detail.contains("«DE»"));

    f.alternative = None;
    let d = conclude(&f);
    assert_eq!(d.fix, None);
    assert!(d.detail.contains("обновите подписку"));
}

#[test]
fn dns_failure_without_alternative_opens_dns_check() {
    let mut f = base();
    f.server_tcp = Some(QuickResult::DnsFailed);
    f.alternative = None;
    assert_eq!(conclude(&f).fix, Some(Fix::OpenDnsCheck));
}

#[test]
fn frozen_server() {
    let mut f = base();
    f.probe = Some(ProbeFact::Done(Verdict::DataFrozen));
    let d = conclude(&f);
    assert_eq!(d.title, "Провайдер блокирует этот сервер");
    assert!(matches!(d.fix, Some(Fix::SwitchServer { .. })));
}

#[test]
fn connected_and_tunnel_works() {
    let mut f = base();
    f.service = Some(ServiceStatus::Connected {
        core: CoreKind::Xray,
    });
    f.internet = None;
    f.probe = None;
    f.tunnel = Some(Ok(Trace {
        country: Some("NL".into()),
        ms: 120,
    }));
    let d = conclude(&f);
    assert_eq!(d.tone, Tone::Ok);
    assert!(d.detail.contains("NL"));
    assert!(!d.steps.iter().any(|s| s.title == "Интернет без VPN"));
}

#[test]
fn connected_but_no_data() {
    let mut f = base();
    f.service = Some(ServiceStatus::Connected {
        core: CoreKind::Xray,
    });
    f.probe = None;
    f.tunnel = Some(Err("нет ответа".into()));
    let d = conclude(&f);
    assert_eq!(d.title, "Подключение есть, но данные не идут");
    assert!(matches!(d.fix, Some(Fix::SwitchServer { key, .. }) if key == "k3"));
}

#[test]
fn zapret_mode_offers_autoselect() {
    let mut f = base();
    f.service = Some(ServiceStatus::Zapret {
        strategy: "general (ALT4)".into(),
    });
    let d = conclude(&f);
    assert_eq!(d.tone, Tone::Ok);
    assert!(d.detail.contains("ALT4"));
    assert_eq!(d.fix, Some(Fix::ZapretAutoselect));
}

#[test]
fn postponed_probe_does_not_alarm() {
    let mut f = base();
    f.probe = Some(ProbeFact::Postponed);
    let d = conclude(&f);
    assert_eq!(d.tone, Tone::Warning);
    assert_eq!(d.fix, Some(Fix::Connect));
}
