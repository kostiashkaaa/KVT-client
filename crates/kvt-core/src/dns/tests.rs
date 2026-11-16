//! Тесты проверки DNS: перехват, подмена, FakeIP, рекомендации.

use super::resolvers::{is_bogon, YANDEX_NETS};
use super::*;
use std::net::Ipv4Addr;

const ISP: Ipv4Addr = Ipv4Addr::new(212, 48, 193, 5);

fn ok(ips: &[Ipv4Addr]) -> QueryResult {
    QueryResult::Answer {
        answer: Answer {
            rcode: 0,
            a: ips.to_vec(),
            ..Answer::default()
        },
        ms: 20,
    }
}

fn rcode(code: u8) -> QueryResult {
    QueryResult::Answer {
        answer: Answer {
            rcode: code,
            ..Answer::default()
        },
        ms: 20,
    }
}

/// Честная сеть: каждый резолвер отвечает из своих сетей.
fn honest() -> Observations {
    let egress = |id: &str| match id {
        "yandex" => Ipv4Addr::new(87, 250, 250, 1),
        "cloudflare" => Ipv4Addr::new(172, 68, 4, 10),
        "google" => Ipv4Addr::new(172, 253, 1, 2),
        "quad9" => Ipv4Addr::new(74, 63, 16, 1),
        _ => Ipv4Addr::new(94, 140, 15, 1),
    };
    let mut obs = Observations {
        system_server: Some(Ipv4Addr::new(192, 168, 1, 1)),
        system_whoami: Some(ok(&[ISP])),
        ..Default::default()
    };
    for r in RESOLVERS {
        for via in [Via::Udp, Via::Dot, Via::Doh] {
            obs.whoami.push((r.id, via, ok(&[egress(r.id)])));
        }
    }
    let fb = [Ipv4Addr::new(157, 240, 205, 35)];
    let rt = [
        Ipv4Addr::new(104, 21, 32, 39),
        Ipv4Addr::new(172, 67, 182, 196),
    ];
    for source in [
        Source::System,
        Source::Resolver("google", Via::Udp),
        Source::Resolver("cloudflare", Via::Doh),
    ] {
        obs.spoof.push((SPOOF_DOMAINS[0], source, ok(&fb)));
        obs.spoof.push((SPOOF_DOMAINS[1], source, ok(&rt)));
    }
    obs
}

fn set_whoami(obs: &mut Observations, id: &str, via: Via, r: QueryResult) {
    for entry in &mut obs.whoami {
        if entry.0 == id && entry.1 == via {
            entry.2 = r.clone();
        }
    }
}

fn set_spoof(obs: &mut Observations, source: Source, domain: &str, r: QueryResult) {
    for entry in &mut obs.spoof {
        if entry.0 == domain && entry.1 == source {
            entry.2 = r.clone();
        }
    }
}

#[test]
fn honest_network() {
    let report = analyze(&honest());
    assert_eq!(report.tone, Tone::Ok);
    assert!(!report.interception);
    assert!(report.spoofing.is_empty());
    assert!(report.encrypted_available);
    assert_eq!(report.recommended_local, "yandex");
    assert!(report
        .resolvers
        .iter()
        .all(|r| matches!(r.udp, PathStatus::Works { .. })));
}

#[test]
fn transparent_proxy_on_port_53() {
    let mut obs = honest();
    for r in RESOLVERS {
        set_whoami(&mut obs, r.id, Via::Udp, ok(&[ISP]));
    }
    let report = analyze(&obs);
    assert!(report.interception);
    assert_eq!(report.tone, Tone::Warning);
    for r in &report.resolvers {
        assert_eq!(
            r.udp,
            PathStatus::Intercepted { ms: 20, by: ISP },
            "{}",
            r.id
        );
    }
    // Никто не отвечает сам — для прямых сайтов остаётся Яндекс (ответит провайдер).
    assert_eq!(report.recommended_local, "yandex");
}

/// Ответ не из сетей Google, но DoH тоже недоступен и с провайдером не совпадает:
/// таблица могла устареть — перехват не засчитываем.
#[test]
fn unknown_egress_without_confirmation_is_not_interception() {
    let mut obs = honest();
    set_whoami(
        &mut obs,
        "google",
        Via::Udp,
        ok(&[Ipv4Addr::new(35, 1, 2, 3)]),
    );
    set_whoami(&mut obs, "google", Via::Doh, QueryResult::Timeout);
    set_whoami(&mut obs, "google", Via::Dot, QueryResult::Timeout);
    let report = analyze(&obs);
    assert!(!report.interception);
}

#[test]
fn unknown_egress_confirmed_by_doh_is_interception() {
    let mut obs = honest();
    let other = Ipv4Addr::new(35, 1, 2, 3);
    set_whoami(&mut obs, "google", Via::Udp, ok(&[other]));
    let report = analyze(&obs);
    let google = report.resolvers.iter().find(|r| r.id == "google").unwrap();
    assert_eq!(google.udp, PathStatus::Intercepted { ms: 20, by: other });
}

/// Windows настроена на 8.8.8.8: DNS сети и Google совпадают, но это не перехват.
#[test]
fn system_dns_set_to_google_is_not_interception() {
    let mut obs = honest();
    let g = Ipv4Addr::new(172, 253, 1, 2);
    obs.system_whoami = Some(ok(&[g]));
    let report = analyze(&obs);
    assert!(!report.interception);
}

#[test]
fn blocked_encrypted_dns() {
    let mut obs = honest();
    for r in RESOLVERS {
        set_whoami(&mut obs, r.id, Via::Dot, QueryResult::Timeout);
        set_whoami(&mut obs, r.id, Via::Doh, QueryResult::Failed("tls".into()));
    }
    let report = analyze(&obs);
    assert!(!report.encrypted_available);
    assert!(report.detail.contains("DoH и DoT"));
    let cf = &report.resolvers[1];
    assert_eq!(cf.dot, PathStatus::Blocked);
    assert!(matches!(cf.doh, PathStatus::Failed { .. }));
}

#[test]
fn stub_address_for_both_sites() {
    let mut obs = honest();
    let stub = Ipv4Addr::new(195, 208, 152, 206);
    for d in SPOOF_DOMAINS {
        set_spoof(&mut obs, Source::System, d, ok(&[stub]));
    }
    let report = analyze(&obs);
    assert_eq!(report.spoofing.len(), 2);
    assert!(report
        .spoofing
        .iter()
        .all(|f| f.kind == SpoofKind::Stub && f.source == "DNS сети"));
    assert_eq!(
        report.title,
        "DNS подменяет ответы для заблокированных сайтов"
    );
}

/// Роутер с podkop: FakeIP — не подмена, а свой обход.
#[test]
fn router_fake_ip_is_not_spoofing() {
    let mut obs = honest();
    let fake = [
        Ipv4Addr::new(198, 18, 11, 149),
        Ipv4Addr::new(198, 18, 10, 173),
    ];
    for (domain, ip) in SPOOF_DOMAINS.into_iter().zip(fake) {
        set_spoof(&mut obs, Source::System, domain, ok(&[ip]));
    }
    let report = analyze(&obs);
    assert!(report.fake_ip);
    assert!(report.spoofing.is_empty());
    assert_eq!(report.tone, Tone::Ok);
    assert_eq!(report.title, "На роутере работает обход блокировок");
}

#[test]
fn private_address_is_stub() {
    let mut obs = honest();
    set_spoof(
        &mut obs,
        Source::Resolver("google", Via::Udp),
        SPOOF_DOMAINS[0],
        ok(&[Ipv4Addr::new(10, 10, 34, 34)]),
    );
    let report = analyze(&obs);
    assert_eq!(report.spoofing.len(), 1);
    assert_eq!(report.spoofing[0].source, "Google (UDP)");
}

#[test]
fn nxdomain_while_doh_resolves() {
    let mut obs = honest();
    set_spoof(
        &mut obs,
        Source::System,
        SPOOF_DOMAINS[1],
        rcode(wire::RCODE_NXDOMAIN),
    );
    let report = analyze(&obs);
    assert_eq!(report.spoofing.len(), 1);
    assert_eq!(report.spoofing[0].kind, SpoofKind::Denied);
    assert_eq!(report.spoofing[0].domain, "rutracker.org");
}

#[test]
fn encrypted_answers_are_never_reported() {
    let mut obs = honest();
    let stub = Ipv4Addr::new(10, 0, 0, 1);
    for d in SPOOF_DOMAINS {
        set_spoof(
            &mut obs,
            Source::Resolver("cloudflare", Via::Doh),
            d,
            ok(&[stub]),
        );
    }
    assert!(analyze(&obs)
        .spoofing
        .iter()
        .all(|f| !f.source.contains("DoH")));
}

#[test]
fn nets() {
    assert!(in_nets(Ipv4Addr::new(172, 68, 1, 1), CLOUDFLARE_NETS));
    assert!(!in_nets(Ipv4Addr::new(77, 88, 8, 8), CLOUDFLARE_NETS));
    assert!(in_nets(Ipv4Addr::new(77, 88, 8, 8), YANDEX_NETS));
    assert!(in_nets(
        Ipv4Addr::new(1, 2, 3, 4),
        &[(Ipv4Addr::UNSPECIFIED, 0)]
    ));
    assert!(is_bogon(Ipv4Addr::new(100, 64, 0, 1)));
    assert!(!is_bogon(Ipv4Addr::new(100, 128, 0, 1)));
}
