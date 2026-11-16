//! Тесты аудита: разбор фактов и выводы по каждой группе проверок.

use super::*;
use base64::Engine as _;

fn own() -> OwnDirs {
    own_dirs(&[r"C:\Program Files\KVT", r"C:\ProgramData\KVT"])
}

fn find<'a>(f: &'a [Finding], title: &str) -> &'a Finding {
    f.iter()
        .find(|x| x.title.starts_with(title))
        .unwrap_or_else(|| panic!("нет находки «{title}» в {f:#?}"))
}

fn winhttp(flags: u32, proxy: &str) -> String {
    let mut raw = Vec::new();
    raw.extend_from_slice(&0x28u32.to_le_bytes());
    raw.extend_from_slice(&5u32.to_le_bytes());
    raw.extend_from_slice(&flags.to_le_bytes());
    raw.extend_from_slice(&(proxy.len() as u32).to_le_bytes());
    raw.extend_from_slice(proxy.as_bytes());
    raw.extend_from_slice(&0u32.to_le_bytes());
    base64::engine::general_purpose::STANDARD.encode(raw)
}

#[test]
fn clean_machine_has_only_ok() {
    let f = analyze(&Facts::default(), &own());
    assert!(f.iter().all(|x| x.level == Level::Ok), "{f:#?}");
    assert!(f.iter().all(|x| x.fix.is_none()));
    for g in [Group::Leaks, Group::Conflicts, Group::Zapret] {
        assert!(f.iter().any(|x| x.group == g));
    }
}

#[test]
fn script_output_is_parsed() {
    let json = r#"{"proxy":{"enable":1,"server":"127.0.0.1:10808","autoConfigUrl":""},
            "winhttp":"","teredo":{"type":"Default","state":"Offline"},
            "adapters":[{"name":"Ethernet","description":"Realtek","status":"Up","staticDns":"8.8.8.8,1.1.1.1"}],
            "processes":[{"pid":42,"name":"v2rayN","path":"C:\\v2rayN\\v2rayN.exe"}],
            "antivirus":["Windows Defender"],
            "services":[],
            "autostart":[{"location":"hkcu_run","name":"zapret","command":"C:\\z\\general.bat","disabled":false}],
            "browsers":[{"browser":"chrome","mode":"secure","templates":"https://dns.google/dns-query{?dns}"}]}"#;
    let facts = parse_facts(&format!("\u{feff}{json}\r\n")).unwrap();
    assert_eq!(facts.processes[0].pid, 42);
    let f = analyze(&facts, &own());
    assert_eq!(
        find(&f, "Включён системный прокси").fix,
        Some(Fix::DisableSystemProxy)
    );
    assert!(find(&f, "Включён системный прокси")
        .detail
        .contains("127.0.0.1:10808"));
    assert!(find(&f, "DNS прописан вручную")
        .detail
        .contains("8.8.8.8, 1.1.1.1"));
    assert_eq!(
        find(&f, "Запущен v2rayN").fix,
        Some(Fix::CloseProcess {
            pid: 42,
            name: "v2rayN".into()
        })
    );
    assert!(find(&f, "Браузер использует свой DNS")
        .detail
        .contains("dns.google"));
    assert!(matches!(
        find(&f, "Автозапуск zapret: zapret").fix,
        Some(Fix::DisableUserAutostart { .. })
    ));
}

#[test]
fn empty_or_broken_output_is_error_not_panic() {
    assert!(parse_facts("").is_err());
    assert!(parse_facts("not json").is_err());
    assert_eq!(parse_facts("{}").unwrap(), Facts::default());
}

#[test]
fn winhttp_proxy_is_read_only_when_flag_set() {
    assert_eq!(
        winhttp_proxy(&winhttp(3, "127.0.0.1:2080")).as_deref(),
        Some("127.0.0.1:2080")
    );
    assert_eq!(winhttp_proxy(&winhttp(1, "")), None);
    assert_eq!(winhttp_proxy(""), None);
    assert_eq!(winhttp_proxy("!!!"), None);
    let facts = Facts {
        winhttp: winhttp(3, "127.0.0.1:2080"),
        ..Default::default()
    };
    assert_eq!(
        find(&analyze(&facts, &own()), "Прокси WinHTTP").fix,
        Some(Fix::Service(ServiceFix::ResetWinHttpProxy))
    );
}

#[test]
fn teredo_only_when_active() {
    let mut facts = Facts {
        teredo: Teredo {
            kind: "Default".into(),
            state: "Qualified".into(),
        },
        ..Default::default()
    };
    assert_eq!(
        find(&analyze(&facts, &own()), "Включён Teredo").level,
        Level::Warning
    );
    facts.teredo = Teredo {
        kind: "Disabled".into(),
        state: "Qualified".into(),
    };
    assert_eq!(find(&analyze(&facts, &own()), "Teredo").level, Level::Ok);
    facts.teredo = Teredo {
        kind: "Default".into(),
        state: "Offline".into(),
    };
    assert_eq!(find(&analyze(&facts, &own()), "Teredo").level, Level::Ok);
}

#[test]
fn own_cores_and_adapter_are_not_conflicts() {
    let facts = Facts {
        processes: vec![
            Process {
                pid: 1,
                name: "xray".into(),
                path: r"C:\Program Files\KVT\cores\xray.exe".into(),
            },
            // Путь неизвестен (ядро запустила служба) — не считаем чужим.
            Process {
                pid: 2,
                name: "sing-box".into(),
                path: String::new(),
            },
            Process {
                pid: 3,
                name: "winws".into(),
                path: r"C:\Program Files\KVT\zapret\bin\winws.exe".into(),
            },
            Process {
                pid: 4,
                name: "winws".into(),
                path: r"C:\ProgramData\KVT\zapret-bundle\bin\winws.exe".into(),
            },
        ],
        adapters: vec![Adapter {
            name: "KVT".into(),
            description: "Wintun Userspace Tunnel".into(),
            status: "Up".into(),
            static_dns: "172.19.0.2".into(),
        }],
        ..Default::default()
    };
    let f = analyze(&facts, &own());
    assert!(f.iter().all(|x| x.level == Level::Ok), "{f:#?}");
}

#[test]
fn foreign_core_and_tunnel_are_reported() {
    let facts = Facts {
        processes: vec![Process {
            pid: 7,
            name: "sing-box".into(),
            path: r"C:\Hiddify\sing-box.exe".into(),
        }],
        adapters: vec![Adapter {
            name: "OpenVPN".into(),
            description: "TAP-Windows Adapter V9".into(),
            status: "Up".into(),
            static_dns: String::new(),
        }],
        ..Default::default()
    };
    let f = analyze(&facts, &own());
    assert_eq!(find(&f, "Запущен sing-box").level, Level::Warning);
    assert_eq!(
        find(&f, "Активен туннель другого VPN").level,
        Level::Warning
    );
}

#[test]
fn https_scanning_antivirus_is_info() {
    let facts = Facts {
        antivirus: vec!["Windows Defender".into(), "Kaspersky Plus".into()],
        ..Default::default()
    };
    let a = find(&analyze(&facts, &own()), "Антивирус проверяет HTTPS").clone();
    assert_eq!(a.level, Level::Info);
    assert!(a.detail.contains("Kaspersky") && !a.detail.contains("Defender"));
}

#[test]
fn foreign_zapret_service_and_autostart() {
    let facts = Facts {
        services: vec![
            Service {
                name: "zapret".into(),
                display_name: "zapret".into(),
                state: "Running".into(),
                start_mode: "Auto".into(),
                path: r"C:\zapret\bin\winws.exe --wf-tcp=443".into(),
            },
            Service {
                name: "kvt-zapret".into(),
                display_name: String::new(),
                state: "Running".into(),
                start_mode: "Auto".into(),
                path: r"C:\Program Files\KVT\zapret\bin\winws.exe".into(),
            },
        ],
        autostart: vec![
            Autostart {
                location: Location::Task,
                name: r"\zapret autostart".into(),
                command: r"C:\zapret\service.bat".into(),
                disabled: false,
            },
            Autostart {
                location: Location::HklmRun,
                name: "GoodbyeDPI".into(),
                command: r"C:\gdpi\goodbyedpi.exe".into(),
                disabled: true,
            },
            Autostart {
                location: Location::HkcuRun,
                name: "Telegram".into(),
                command: r"C:\Telegram\Telegram.exe -autostart".into(),
                disabled: false,
            },
        ],
        ..Default::default()
    };
    let f = analyze(&facts, &own());
    assert_eq!(
        find(&f, "Работает другая сборка zapret").fix,
        Some(Fix::StopZapret)
    );
    assert_eq!(
        find(&f, "Служба zapret запускается").fix,
        Some(Fix::Service(ServiceFix::DisableZapretService {
            name: "zapret".into()
        }))
    );
    assert!(!f.iter().any(|x| x.title.contains("kvt-zapret")));
    let task_id = facts.autostart[0].id();
    assert_eq!(
        find(&f, "Автозапуск zapret").fix,
        Some(Fix::Service(ServiceFix::DisableAutostart { id: task_id }))
    );
    // Отключённая запись и Telegram — не находки.
    assert_eq!(
        f.iter()
            .filter(|x| x.title.starts_with("Автозапуск"))
            .count(),
        1
    );
}

#[test]
fn autostart_id_is_stable_and_distinct() {
    let a = Autostart {
        location: Location::HkcuRun,
        name: "zapret".into(),
        command: "x".into(),
        disabled: false,
    };
    let mut b = a.clone();
    assert_eq!(a.id(), b.id());
    assert_eq!(a.id().len(), 16);
    b.location = Location::HklmRun;
    assert_ne!(a.id(), b.id());
}

#[test]
fn only_vpn_processes_can_be_closed() {
    assert!(is_vpn_process_name("v2rayN.exe"));
    assert!(is_vpn_process_name("sing-box"));
    assert!(!is_vpn_process_name("explorer.exe"));
    assert!(!is_vpn_process_name("kvt.exe"));
}

#[test]
fn firefox_doh_mode_numbers() {
    let mut facts = Facts {
        browsers: vec![BrowserDns {
            browser: "firefox".into(),
            mode: "5".into(),
            templates: String::new(),
        }],
        ..Default::default()
    };
    assert_eq!(
        find(&analyze(&facts, &own()), "DNS в браузерах").level,
        Level::Ok
    );
    facts.browsers[0].mode = "3".into();
    assert_eq!(
        find(&analyze(&facts, &own()), "Браузер использует").level,
        Level::Info
    );
}

#[test]
fn encoded_script_fits_command_line() {
    // Предел командной строки Windows — 32 767 символов.
    let len: usize = powershell_args().iter().map(|a| a.len() + 1).sum();
    assert!(len < 30_000, "{len}");
}

#[test]
fn fix_json_matches_interface() {
    let fix = Fix::Service(ServiceFix::DisableZapretService {
        name: "zapret".into(),
    });
    let json = serde_json::to_value(&fix).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"kind": "service", "action": "disable_zapret_service", "name": "zapret"})
    );
    assert_eq!(serde_json::from_value::<Fix>(json).unwrap(), fix);
    let close: Fix =
        serde_json::from_str(r#"{"kind":"close_process","pid":7,"name":"v2rayN"}"#).unwrap();
    assert_eq!(
        close,
        Fix::CloseProcess {
            pid: 7,
            name: "v2rayN".into()
        }
    );
}

#[test]
fn script_only_reads() {
    for word in [
        "Set-", "Remove-", "New-Item", "Stop-", "Disable-", "reg add", "netsh", "schtasks",
    ] {
        assert!(!SCRIPT.contains(word), "скрипт аудита содержит {word}");
    }
}
