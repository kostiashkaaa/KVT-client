use super::*;
use crate::routing::presets::{self, CustomRule, ListMode, RoutingSettings};
use crate::routing::{Action, RoutingPlan};
use std::time::Duration;

fn def(id: &str) -> &'static ServiceDef {
    all().iter().find(|s| s.id == id).unwrap()
}

/// План, как его собирает `connect_current` в окне (без прокси Telegram).
fn plan(settings: &RoutingSettings, hybrid: bool) -> RoutingPlan {
    let mut plan = presets::from_settings(settings)
        .with_servers(["vpn.example.com".to_string()])
        .with_health_check()
        .with_update_hosts();
    if hybrid {
        plan.extend(presets::zapret_youtube_discord());
    }
    plan
}

fn via_plan(id: &str, plan: &RoutingPlan, telegram: bool) -> Via {
    via(def(id), &Running::Vpn { plan }, telegram)
}

// ── Данные ──

#[test]
fn bundled_file_is_valid() {
    let services = parse(SERVICES_JSON).unwrap();
    // Все пять сервисов из плана 0.9.8 на месте.
    let ids: Vec<&str> = services.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        ["youtube", "discord", "telegram", "instagram", "chatgpt"]
    );
    assert_eq!(all().len(), services.len());
    // Без VPN показываем только то, что zapret и прокси могут открыть.
    let zapret_only: Vec<&str> = for_mode(Mode::Zapret).map(|s| s.id.as_str()).collect();
    assert_eq!(zapret_only, ["youtube", "discord", "telegram"]);
    assert_eq!(for_mode(Mode::Vpn).count(), 5);
    assert_eq!(for_mode(Mode::Hybrid).count(), 5);
}

#[test]
fn probes_are_checked() {
    let probe = |url: &str| Probe::try_from(url.to_string());
    assert_eq!(
        probe("https://www.YouTube.com/a").unwrap().host,
        "www.youtube.com"
    );
    for bad in [
        "http://youtube.com/",
        "https://user:pass@youtube.com/",
        "https://youtube.com:8443/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "ftp://youtube.com/",
        "youtube.com",
        "",
    ] {
        assert!(probe(bad).is_err(), "{bad}");
    }
}

fn file_with(service: &str) -> String {
    format!(r#"{{"services":[{service}]}}"#)
}

#[test]
fn bad_data_is_rejected() {
    let ok = r#"{"id":"a","name":"A","probes":["https://a.example/"],"modes":["vpn"]}"#;
    assert!(parse(&file_with(ok)).is_ok());

    let case = |service: &str| parse(&file_with(service));
    // Неизвестный режим, пустые списки, адрес не https.
    assert!(matches!(
        case(r#"{"id":"a","name":"A","probes":["https://a.example/"],"modes":["wireguard"]}"#),
        Err(ServicesError::Json(_))
    ));
    assert!(matches!(
        case(r#"{"id":"a","name":"A","probes":["http://a.example/"],"modes":["vpn"]}"#),
        Err(ServicesError::Json(_))
    ));
    assert!(matches!(
        case(r#"{"id":"a","name":"A","probes":[],"modes":["vpn"]}"#),
        Err(ServicesError::Invalid { .. })
    ));
    assert!(matches!(
        case(r#"{"id":"a","name":"A","probes":["https://a.example/"],"modes":[]}"#),
        Err(ServicesError::Invalid { .. })
    ));
    // id попадает в путь и в ключи интерфейса.
    assert!(matches!(
        case(r#"{"id":"../a","name":"A","probes":["https://a.example/"],"modes":["vpn"]}"#),
        Err(ServicesError::Invalid { .. })
    ));
    // Набор правил должен быть из каталога.
    assert!(matches!(
        case(
            r#"{"id":"a","name":"A","probes":["https://a.example/"],"sets":["itdog:nope"],"modes":["vpn"]}"#
        ),
        Err(ServicesError::Invalid { .. })
    ));
    // Повтор id.
    assert!(matches!(
        parse(&file_with(&format!("{ok},{ok}"))),
        Err(ServicesError::Invalid { .. })
    ));
    // Не JSON и не тот вид.
    assert!(matches!(parse("not json"), Err(ServicesError::Json(_))));
    assert!(matches!(parse("[]"), Err(ServicesError::Json(_))));
    assert!(matches!(
        parse(r#"{"services":[{}]}"#),
        Err(ServicesError::Json(_))
    ));
    // Слишком много пробных адресов.
    let many = r#"{"id":"a","name":"A","probes":["https://a.example/","https://b.example/","https://c.example/","https://d.example/","https://e.example/"],"modes":["vpn"]}"#;
    assert!(matches!(case(many), Err(ServicesError::Invalid { .. })));
}

#[test]
fn mode_parsing_follows_connect_plan() {
    assert_eq!(Mode::parse(None), Mode::Vpn);
    assert_eq!(Mode::parse(Some("vpn")), Mode::Vpn);
    assert_eq!(Mode::parse(Some("hybrid")), Mode::Hybrid);
    assert_eq!(Mode::parse(Some("zapret")), Mode::Zapret);
    assert_eq!(Mode::parse(Some("что-то")), Mode::Vpn);
}

// ── Путь трафика ──

#[test]
fn default_settings_send_services_through_vpn() {
    let plan = plan(&RoutingSettings::default(), false);
    for id in ["youtube", "discord", "telegram", "instagram", "chatgpt"] {
        assert_eq!(via_plan(id, &plan, false), Via::Vpn, "{id}");
    }
}

#[test]
fn only_blocked_mode_still_routes_blocked_services_through_vpn() {
    // Подводный камень: `resolve_domain` без наборов вернул бы тут «напрямую».
    let settings = RoutingSettings {
        everything_else: Action::Direct,
        ..RoutingSettings::default()
    };
    let plan = plan(&settings, false);
    assert_eq!(plan.resolve_domain("www.youtube.com"), Action::Direct);
    for id in ["youtube", "discord", "telegram", "instagram", "chatgpt"] {
        assert_eq!(via_plan(id, &plan, false), Via::Vpn, "{id}");
    }
}

#[test]
fn full_list_mode_uses_registry_sets() {
    let settings = RoutingSettings {
        list_mode: ListMode::Full,
        everything_else: Action::Direct,
        ..RoutingSettings::default()
    };
    let plan = plan(&settings, false);
    for id in ["youtube", "discord", "telegram", "instagram", "chatgpt"] {
        assert_eq!(via_plan(id, &plan, false), Via::Vpn, "{id}");
    }
}

#[test]
fn user_choice_for_a_list_overrides_the_preset() {
    let mut settings = RoutingSettings::default();
    settings.overrides.insert("youtube".into(), Action::Direct);
    let plan = plan(&settings, false);
    assert_eq!(via_plan("youtube", &plan, true), Via::Direct);
    // Остальные сервисы выбор не задел.
    assert_eq!(via_plan("discord", &plan, true), Via::Vpn);

    settings.overrides.insert("youtube".into(), Action::Block);
    let plan = presets::from_settings(&settings);
    assert_eq!(via_plan("youtube", &plan, true), Via::Blocked);
}

#[test]
fn custom_site_beats_the_list() {
    let settings = RoutingSettings {
        custom: vec![CustomRule {
            target: "youtube.com".into(),
            action: Action::Direct,
        }],
        ..RoutingSettings::default()
    };
    let plan = plan(&settings, false);
    assert_eq!(via_plan("youtube", &plan, true), Via::Direct);
}

#[test]
fn hybrid_sends_youtube_and_discord_to_zapret() {
    let plan = plan(&RoutingSettings::default(), true);
    assert_eq!(via_plan("youtube", &plan, false), Via::Zapret);
    assert_eq!(via_plan("discord", &plan, false), Via::Zapret);
    assert_eq!(via_plan("instagram", &plan, false), Via::Vpn);
    assert_eq!(via_plan("chatgpt", &plan, false), Via::Vpn);
}

#[test]
fn user_choice_beats_zapret_in_hybrid() {
    let mut settings = RoutingSettings::default();
    settings.overrides.insert("youtube".into(), Action::Proxy);
    let plan = plan(&settings, true);
    assert_eq!(via_plan("youtube", &plan, false), Via::Vpn);
    assert_eq!(via_plan("discord", &plan, false), Via::Zapret);
}

/// План, как его собирает `connect_current`, вместе с правилами прокси Telegram
/// (они добавляются, когда прокси включён, в любом режиме).
fn plan_with_proxy(hybrid: bool, route: crate::tgproxy::Route) -> RoutingPlan {
    let mut plan = plan(&RoutingSettings::default(), hybrid);
    plan.extend(crate::tgproxy::route_rules(
        &["abc.co.uk".to_string()],
        hybrid,
        route,
    ));
    plan.validate().unwrap();
    plan
}

#[test]
fn telegram_goes_through_its_proxy_in_every_mode_when_it_is_on() {
    use crate::tgproxy::Route;
    // Прокси работает при любом подключении, а Telegram Desktop всегда подключён к нему.
    for (hybrid, route) in [
        (false, Route::Direct),
        (true, Route::Direct),
        (true, Route::VpnFirst),
    ] {
        let plan = plan_with_proxy(hybrid, route);
        assert_eq!(
            via_plan("telegram", &plan, true),
            Via::Proxy,
            "{hybrid} {route:?}"
        );
        // Остальные сервисы правила прокси не задели.
        assert_eq!(via_plan("instagram", &plan, true), Via::Vpn);
    }
    // Прокси выключен — Telegram идёт по правилам, как всё остальное.
    let plain = plan(&RoutingSettings::default(), false);
    assert_eq!(via_plan("telegram", &plain, false), Via::Vpn);
}

#[test]
fn telegram_probe_follows_the_route_of_the_proxy_upstream() {
    use crate::tgproxy::Route;
    // Проба берёт адрес, куда прокси открывает WebSocket, и идёт по правилу этого
    // адреса: в режиме «VPN» и «сначала VPN» — через туннель, в «Гибриде» с путём
    // «мимо VPN» — напрямую, как и сам прокси.
    let sets = |plan: &RoutingPlan| {
        plan.resolve_host(def("telegram").host(), |s| {
            def("telegram").sets.iter().any(|x| x == s)
        })
    };
    assert_eq!(sets(&plan_with_proxy(false, Route::Direct)), Action::Proxy);
    assert_eq!(sets(&plan_with_proxy(true, Route::VpnFirst)), Action::Proxy);
    assert_eq!(sets(&plan_with_proxy(true, Route::Direct)), Action::Direct);
}

#[test]
fn zapret_only_mode() {
    let running = Running::Zapret;
    assert_eq!(via(def("youtube"), &running, true), Via::Zapret);
    assert_eq!(via(def("discord"), &running, false), Via::Zapret);
    assert_eq!(via(def("telegram"), &running, true), Via::Proxy);
    // Без прокси Telegram zapret не помогает: список Flowseal его не покрывает.
    assert_eq!(via(def("telegram"), &running, false), Via::Direct);
    assert_eq!(via(def("instagram"), &running, true), Via::Direct);
}

#[test]
fn nothing_running_means_direct_whatever_the_mode() {
    for id in ["youtube", "discord", "telegram", "instagram", "chatgpt"] {
        assert_eq!(via(def(id), &Running::Off, true), Via::Direct, "{id}");
    }
}

// ── Вердикт ──

fn answered() -> Sample {
    Sample {
        dns_resolved: true,
        answered: true,
        first_byte: Some(Duration::from_millis(150)),
        bytes: SAMPLE_BYTES,
        read: Duration::from_millis(400),
        complete: true,
        timed_out: false,
    }
}

#[test]
fn healthy_service_works() {
    assert_eq!(classify(&answered()), Health::Works);
}

#[test]
fn small_page_is_not_slow_however_long_it_took() {
    // Страница в несколько килобайт: по времени чтения о скорости не судим.
    let s = Sample {
        bytes: 1_500,
        read: Duration::from_secs(5),
        ..answered()
    };
    assert_eq!(classify(&s), Health::Works);
}

#[test]
fn slow_start_or_slow_read_is_slow() {
    let late = Sample {
        first_byte: Some(Duration::from_secs(4)),
        ..answered()
    };
    assert_eq!(classify(&late), Health::Slow);
    let throttled = Sample {
        read: Duration::from_secs(4),
        ..answered()
    };
    assert_eq!(classify(&throttled), Health::Slow);
}

#[test]
fn data_that_trickles_is_slow_not_cut() {
    // Несколько килобайт за десять секунд: не обрыв, а сильное замедление.
    let trickle = Sample {
        bytes: 9 * 1024,
        read: Duration::from_secs(10),
        complete: false,
        timed_out: true,
        ..answered()
    };
    assert_eq!(classify(&trickle), Health::Slow);
    assert!(!classify(&trickle).is_freeze());
}

#[test]
fn failures_say_why() {
    let no_dns = Sample {
        dns_resolved: false,
        ..Sample::default()
    };
    assert_eq!(classify(&no_dns), Health::Down(Cause::Dns));

    let silent = Sample {
        dns_resolved: true,
        ..Sample::default()
    };
    assert_eq!(classify(&silent), Health::Down(Cause::Unreachable));

    // Ответ начался и встал на 16 КБ — заморозка по объёму.
    let cut = Sample {
        bytes: 16 * 1024,
        complete: false,
        ..answered()
    };
    assert_eq!(classify(&cut), Health::Down(Cause::Cut));
    assert!(classify(&cut).is_freeze());
    assert!(!classify(&silent).is_freeze());
    assert!(!Health::Slow.is_freeze());
}

#[test]
fn service_is_as_bad_as_its_worst_probe() {
    use Cause::*;
    assert_eq!(worst([]), None);
    assert_eq!(
        worst([Health::Works, Health::Slow, Health::Works]),
        Some(Health::Slow)
    );
    assert_eq!(
        worst([Health::Slow, Health::Down(Cut), Health::Down(Dns)]),
        Some(Health::Down(Cut))
    );
    assert_eq!(worst([Health::Works]), Some(Health::Works));
}
