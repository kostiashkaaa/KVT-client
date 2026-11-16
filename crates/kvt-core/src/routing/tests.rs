//! Тесты маршрутизации: правила и разрешение доменов, наборы, настройки, свои сайты.

use super::presets::*;
use super::*;

fn russia_smart(final_action: Action) -> RoutingPlan {
    super::presets::russia_smart(final_action, ListMode::Compact)
}

#[test]
fn update_hosts_go_through_vpn_but_not_the_rest_of_github() {
    let plan = russia_smart(Action::Direct).with_update_hosts();
    assert_eq!(plan.resolve_domain("github.com"), Action::Proxy);
    assert_eq!(
        plan.resolve_domain("raw.githubusercontent.com"),
        Action::Proxy
    );
    assert_eq!(plan.resolve_domain("gist.github.com"), Action::Direct);
    assert!(plan.validate().is_ok());
}

#[test]
fn health_check_goes_through_vpn_even_when_everything_else_is_direct() {
    let mut plan = russia_smart(Action::Direct).with_health_check();
    plan.push(Rule {
        layer: Layer::User,
        matcher: Matcher::DomainSuffix("cloudflare.com".into()),
        action: Action::Direct,
    });
    assert!(plan.validate().is_ok());
    assert_eq!(plan.resolve_domain(HEALTH_HOST), Action::Proxy);
}

#[test]
fn presets_use_only_known_rule_sets() {
    for mode in [ListMode::Compact, ListMode::Full] {
        let plan = super::presets::russia_smart(Action::Proxy, mode);
        assert!(plan.validate().is_ok(), "{mode:?}");
    }
}

#[test]
fn list_choice_overrides_preset() {
    let mut plan = russia_smart(Action::Proxy);
    plan.push(list_choice("youtube", Action::Direct).unwrap());
    let first = plan
        .ordered()
        .into_iter()
        .find(|r| r.layer == Layer::User)
        .unwrap();
    assert_eq!(first.matcher, Matcher::RuleSet("itdog:youtube".into()));
    assert!(plan.validate().is_ok());
    assert!(list_choice("../../evil", Action::Proxy).is_none());
}

#[test]
fn settings_build_valid_plan_and_skip_bad_values() {
    let mut s = RoutingSettings::default();
    s.overrides.insert("youtube".into(), Action::Direct);
    s.overrides.insert("tiktok".into(), Action::Block);
    s.overrides.insert("discord".into(), Action::Zapret);
    s.overrides.insert("../../evil".into(), Action::Proxy);
    s.everything_else = Action::Block;
    let plan = from_settings(&s);
    assert!(plan.validate().is_ok());
    assert_eq!(plan.final_action, Action::Proxy);
    let user: Vec<_> = plan
        .ordered()
        .into_iter()
        .filter(|r| r.layer == Layer::User)
        .collect();
    assert_eq!(user.len(), 2);
    assert!(user.iter().any(
        |r| r.matcher == Matcher::RuleSet("itdog:youtube".into()) && r.action == Action::Direct
    ));
}

#[test]
fn settings_json_is_tolerant() {
    let s: RoutingSettings = serde_json::from_str(r#"{"listMode":"full"}"#).unwrap();
    assert_eq!(s.list_mode, ListMode::Full);
    assert_eq!(s.everything_else, Action::Proxy);
}

fn custom(target: &str) -> Result<Matcher, &'static str> {
    custom_matcher(target)
}

#[test]
fn custom_targets_are_normalized() {
    let d = |s: &str| Ok(Matcher::DomainSuffix(s.into()));
    let ip = |s: &str| Ok(Matcher::IpCidr(s.into()));
    assert_eq!(custom("Example.COM"), d("example.com"));
    assert_eq!(custom("https://www.example.com/a?b#c"), d("example.com"));
    assert_eq!(custom("*.example.com"), d("example.com"));
    assert_eq!(custom("user:pw@example.com:8443/x"), d("example.com"));
    assert_eq!(custom("пример.рф"), d("xn--e1afmkfd.xn--p1ai"));
    assert_eq!(
        custom_display("https://www.Пример.РФ/путь").unwrap(),
        "пример.рф"
    );
    assert_eq!(custom_display("WWW.Example.com").unwrap(), "example.com");
    assert_eq!(custom_display("10.1.2.3/8").unwrap(), "10.0.0.0/8");
    assert_eq!(custom_display("1.2.3.4/32").unwrap(), "1.2.3.4");
    assert_eq!(custom_display("[2001:db8::1]:443").unwrap(), "2001:db8::1");
    assert_eq!(custom(" sub.example.org. "), d("sub.example.org"));
    assert_eq!(custom("1.2.3.4"), ip("1.2.3.4/32"));
    assert_eq!(custom("http://1.2.3.4:8080/"), ip("1.2.3.4/32"));
    assert_eq!(custom("10.1.2.3/8"), ip("10.0.0.0/8"));
    assert_eq!(custom("2001:db8::1"), ip("2001:db8::1/128"));
    assert_eq!(custom("[2001:db8::1]:443"), ip("2001:db8::1/128"));
    assert_eq!(custom("2001:db8:1::/48"), ip("2001:db8:1::/48"));
}

#[test]
fn bad_custom_targets_are_rejected() {
    for bad in [
        "",
        "   ",
        "two words.com",
        "0.0.0.0/0",
        "1.2.3.4/33",
        "1.2.3.4/x",
        "::/0",
        "exa_mple.com",
        "-bad.com",
        "регулярка.*",
        "regexp:.*",
        "domain:evil.com",
        "a..b",
        "[::1",
    ] {
        assert!(custom(bad).is_err(), "{bad:?}");
    }
    let long = format!("{}.com", "a".repeat(400));
    assert!(custom(&long).is_err());
}

#[test]
fn custom_rules_beat_lists_and_skip_bad_values() {
    let mut s = RoutingSettings::default();
    s.overrides.insert("youtube".into(), Action::Direct);
    s.custom = vec![
        CustomRule {
            target: "https://www.YouTube.com/watch".into(),
            action: Action::Proxy,
        },
        CustomRule {
            target: "youtube.com".into(),
            action: Action::Block,
        },
        CustomRule {
            target: "gosuslugi.ru".into(),
            action: Action::Proxy,
        },
        CustomRule {
            target: "discord.com".into(),
            action: Action::Zapret,
        },
        CustomRule {
            target: "not a site".into(),
            action: Action::Direct,
        },
    ];
    let plan = from_settings(&s);
    assert!(plan.validate().is_ok());
    // Повтор не перекрывает первое правило; zapret и мусор пропущены.
    assert_eq!(custom_rules(&s.custom).len(), 2);
    let user: Vec<_> = plan
        .ordered()
        .into_iter()
        .filter(|r| r.layer == Layer::User)
        .collect();
    assert_eq!(user[0].matcher, Matcher::DomainSuffix("youtube.com".into()));
    assert_eq!(user[0].action, Action::Proxy);
    assert_eq!(plan.resolve_domain("m.youtube.com"), Action::Proxy);
    // Свой сайт сильнее пресета «.ru напрямую».
    assert_eq!(plan.resolve_domain("www.gosuslugi.ru"), Action::Proxy);
}

#[test]
fn narrow_custom_rule_wins_regardless_of_order() {
    let s = RoutingSettings {
        custom: vec![
            CustomRule {
                target: "example.com".into(),
                action: Action::Direct,
            },
            CustomRule {
                target: "mail.example.com".into(),
                action: Action::Proxy,
            },
            CustomRule {
                target: "10.20.0.0/16".into(),
                action: Action::Proxy,
            },
            CustomRule {
                target: "10.20.30.0/24".into(),
                action: Action::Block,
            },
        ],
        ..Default::default()
    };
    let plan = from_settings(&s);
    assert_eq!(plan.resolve_domain("mail.example.com"), Action::Proxy);
    assert_eq!(plan.resolve_domain("www.example.com"), Action::Direct);
    let ips: Vec<_> = plan
        .ordered()
        .into_iter()
        .filter_map(|r| match (&r.layer, &r.matcher) {
            (Layer::User, Matcher::IpCidr(c)) => Some(c.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(ips, ["10.20.30.0/24", "10.20.0.0/16"]);
}

#[test]
fn custom_rules_are_capped() {
    let custom: Vec<_> = (0..MAX_CUSTOM_RULES + 50)
        .map(|i| CustomRule {
            target: format!("site{i}.example.com"),
            action: Action::Direct,
        })
        .collect();
    assert_eq!(custom_rules(&custom).len(), MAX_CUSTOM_RULES);
}

#[test]
fn user_direct_drops_domain_from_zapret() {
    let mut plan = hybrid();
    plan.extend(custom_rules(&[CustomRule {
        target: "youtube.com".into(),
        action: Action::Direct,
    }]));
    assert_eq!(plan.resolve_domain("youtube.com"), Action::Direct);
    assert!(!plan.zapret_hostlist().contains(&"youtube.com".to_string()));
    assert!(plan.validate().is_ok());
}

#[test]
fn windows_update_goes_direct_but_not_all_of_microsoft() {
    let plan = russia_smart(Action::Proxy);
    for host in [
        "fe3.delivery.mp.microsoft.com",
        "download.windowsupdate.com",
        "sls.update.microsoft.com",
        "definitionupdates.microsoft.com",
    ] {
        assert_eq!(plan.resolve_domain(host), Action::Direct, "{host}");
    }
    assert_eq!(plan.resolve_domain("microsoft.com"), Action::Proxy);
    assert_eq!(plan.resolve_domain("login.live.com"), Action::Proxy);
    // Свой сайт перекрывает пресет.
    let mut s = RoutingSettings::default();
    s.custom.push(CustomRule {
        target: "windowsupdate.com".into(),
        action: Action::Proxy,
    });
    assert_eq!(
        from_settings(&s).resolve_domain("download.windowsupdate.com"),
        Action::Proxy
    );
}

#[test]
fn old_settings_without_custom_load() {
    let s: RoutingSettings =
        serde_json::from_str(r#"{"listMode":"compact","everythingElse":"direct","overrides":{}}"#)
            .unwrap();
    assert!(s.custom.is_empty());
    let s: RoutingSettings = serde_json::from_str(
        r#"{"custom":[{"target":"example.com","action":"direct"},{"target":"x","action":"weird"}]}"#,
    )
    .unwrap();
    assert_eq!(s.custom.len(), 1);
}

#[test]
fn unknown_rule_set_is_rejected() {
    let mut plan = russia_smart(Action::Proxy);
    plan.push(Rule {
        layer: Layer::Provider,
        matcher: Matcher::RuleSet("rf:../../windows".into()),
        action: Action::Proxy,
    });
    assert!(matches!(
        plan.validate(),
        Err(RoutingError::UnknownRuleSet(_))
    ));
}

/// Злой клиент службы: префиксы ядра, пути, имя процесса с путём — отказ;
/// обычные домены, подсети и имена программ — проходят.
#[test]
fn bad_matcher_strings_are_rejected() {
    let bad = [
        Matcher::IpCidr(r"ext:..\..\x.dat:tag".into()),
        Matcher::IpCidr("10.0.0.0/33".into()),
        Matcher::Domain("regexp:.*".into()),
        Matcher::DomainSuffix("a..b".into()),
        Matcher::DomainSuffix(".example.com".into()),
        Matcher::DomainKeyword("geosite:ru".into()),
        Matcher::ProcessName(r"C:\Windows\x.exe".into()),
        Matcher::ProcessName(String::new()),
    ];
    for matcher in bad {
        let mut plan = russia_smart(Action::Proxy);
        plan.push(Rule {
            layer: Layer::User,
            matcher: matcher.clone(),
            action: Action::Direct,
        });
        assert!(
            matches!(plan.validate(), Err(RoutingError::InvalidMatcher(_))),
            "{matcher:?}"
        );
    }
    let good = [
        Matcher::IpCidr("1.2.3.4".into()),
        Matcher::IpCidr("fe80::/10".into()),
        Matcher::DomainSuffix("xn--e1afmkfd.xn--p1ai".into()),
        Matcher::Domain("_srv.example.com".into()),
        Matcher::DomainKeyword("google".into()),
        Matcher::ProcessName("Telegram.exe".into()),
    ];
    let mut plan = russia_smart(Action::Proxy);
    for matcher in good {
        plan.push(Rule {
            layer: Layer::User,
            matcher,
            action: Action::Direct,
        });
    }
    assert!(plan.validate().is_ok());
}

fn hybrid() -> RoutingPlan {
    let mut plan = russia_smart(Action::Proxy)
        .with_servers(["203.0.113.10".to_string(), "vpn.example.com".into()]);
    plan.extend(zapret_youtube_discord());
    plan
}

#[test]
fn russian_domains_go_direct() {
    let plan = russia_smart(Action::Proxy);
    assert_eq!(plan.resolve_domain("gosuslugi.ru"), Action::Direct);
    assert_eq!(
        plan.resolve_domain("xn--80ajghhoc2aj1c8b.xn--p1ai"),
        Action::Direct
    );
    assert_eq!(plan.resolve_domain("example.com"), Action::Proxy);
    assert_eq!(
        russia_smart(Action::Direct).resolve_domain("example.com"),
        Action::Direct
    );
}

#[test]
fn suffix_does_not_match_partial_labels() {
    let plan = russia_smart(Action::Proxy);
    assert_eq!(plan.resolve_domain("notru"), Action::Proxy);
}

#[test]
fn hybrid_sends_youtube_to_zapret() {
    let plan = hybrid();
    assert!(plan.validate().is_ok());
    assert_eq!(
        plan.resolve_domain("rr3---sn-abc.googlevideo.com"),
        Action::Zapret
    );
    assert!(plan.zapret_hostlist().contains(&"youtube.com".to_string()));
    assert_eq!(
        plan.zapret_exclusions(),
        ["203.0.113.10", "vpn.example.com"]
    );
}

#[test]
fn server_domain_is_never_zapret() {
    let mut plan = RoutingPlan::new(Action::Proxy).with_servers(["edge.discord.com".to_string()]);
    plan.extend(zapret_youtube_discord());
    // Системный слой выше zapret, поэтому адрес сервера остаётся Direct.
    assert_eq!(plan.resolve_domain("edge.discord.com"), Action::Direct);
    assert!(plan.validate().is_ok());
}

#[test]
fn user_rule_overrides_zapret_and_drops_it_from_hostlist() {
    let mut plan = hybrid();
    plan.push(Rule {
        layer: Layer::User,
        matcher: Matcher::DomainSuffix("discord.com".into()),
        action: Action::Proxy,
    });
    assert_eq!(plan.resolve_domain("discord.com"), Action::Proxy);
    assert!(!plan.zapret_hostlist().contains(&"discord.com".to_string()));
}

#[test]
fn provider_cannot_use_zapret() {
    let mut plan = RoutingPlan::new(Action::Proxy);
    plan.push(Rule {
        layer: Layer::Provider,
        matcher: Matcher::DomainSuffix("x.com".into()),
        action: Action::Zapret,
    });
    assert_eq!(plan.validate(), Err(RoutingError::ProviderZapret));
}
