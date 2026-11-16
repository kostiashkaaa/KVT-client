//! Тесты zapret: разбор стратегий, подстановки, списки, релизы.

use super::*;

/// Сокращённый `general.bat` из релиза 1.10.4 — с тем же синтаксисом.
const GENERAL: &str = r#"@echo off
chcp 65001 > nul
cd /d "%~dp0"
call service.bat status_zapret
set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
cd /d %BIN%

start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,2053,%GameFilterTCP% --wf-udp=443,19294-19344,%GameFilterUDP% ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --ip-id=zero --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_www_google_com.bin" --new ^
--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-fooling=ts --dpi-desync-fake-tls=^! --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new ^
--filter-tcp=%GameFilterTCP% --ipset="%LISTS%ipset-all.txt" --dpi-desync=multisplit --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n3
"#;

#[test]
fn parses_flowseal_bat() {
    let s = parse_bat("general", GENERAL).unwrap();
    assert_eq!(s.title, "Основная");
    assert!(s.recommended);
    assert!(s.needs_timestamps);
    assert_eq!(s.args[0], "--wf-tcp=80,443,2053,%GameFilterTCP%");
    assert!(s
        .args
        .contains(&"--hostlist=%LISTS%list-general.txt".to_string()));
    assert!(s.args.contains(&"--dpi-desync-fake-tls=!".to_string()));
    assert_eq!(s.args.iter().filter(|a| *a == "--new").count(), 3);
    assert_eq!(s.args.last().unwrap(), "--dpi-desync-cutoff=n3");
}

#[test]
fn render_substitutes_only_our_directories() {
    let s = parse_bat("general (ALT4)", GENERAL).unwrap();
    assert_eq!(s.title, "ALT4");
    let args = render(
        &s,
        &RenderContext {
            bin: r"C:\Program Files\KVT\zapret\bin\",
            lists: r"C:\ProgramData\KVT\zapret\",
            game: GameFilter::Off,
            interface: Some(7),
        },
    );
    assert_eq!(args[0], "--wf-iface=7");
    assert_eq!(args[1], "--wf-tcp=80,443,2053,12");
    assert!(args.contains(&r"--hostlist=C:\ProgramData\KVT\zapret\list-general.txt".to_string()));
    assert!(args.iter().all(|a| !a.contains('%')));
    let all = render(
        &s,
        &RenderContext {
            bin: "b\\",
            lists: "l\\",
            game: GameFilter::All,
            interface: None,
        },
    );
    assert!(all[0].ends_with("1024-65535"));
}

/// Исключения KVT — в каждом профиле, даже где у Flowseal их нет.
#[test]
fn our_exclusions_reach_every_profile() {
    let s = parse_bat("general (ALT4)", GENERAL).unwrap();
    let args = render(
        &s,
        &RenderContext {
            bin: "b\\",
            lists: "l\\",
            game: GameFilter::Off,
            interface: Some(7),
        },
    );
    let profiles: Vec<&[String]> = args.split(|a| a == "--new").collect();
    assert_eq!(
        profiles.len(),
        s.args.iter().filter(|a| *a == "--new").count() + 1
    );
    for p in &profiles {
        let hostlist = p
            .iter()
            .filter(|a| *a == r"--hostlist-exclude=l\list-exclude-user.txt")
            .count();
        let ipset = p
            .iter()
            .filter(|a| *a == r"--ipset-exclude=l\ipset-exclude-user.txt")
            .count();
        let by_name = p.iter().any(|a| a.starts_with("--hostlist="));
        assert_eq!(ipset, 1, "{p:?}");
        // Профили без имени хоста (игровой фильтр по IP, catch-all) не должны
        // получить хостлист — иначе winws перестанет их выбирать.
        assert_eq!(hostlist, usize::from(by_name), "{p:?}");
    }
    assert!(profiles
        .iter()
        .any(|p| p.iter().any(|a| a.starts_with("--ipset="))
            && !p.iter().any(|a| a.starts_with("--hostlist"))));
    // Общие параметры остаются в начале, до первого профиля.
    assert!(args[0].starts_with("--wf-iface") && args[1].starts_with("--wf-tcp"));
}

#[test]
fn dangerous_flags_and_paths_are_rejected() {
    let wrap = |args: &str| format!("start \"z\" /min \"%BIN%winws.exe\" {args}\n");
    for bad in [
        "--debug=@C:\\Windows\\System32\\evil.dll",
        "--hostlist=C:\\Users\\x\\list.txt",
        "--hostlist=%LISTS%..\\..\\secret.txt",
        "--hostlist=%BIN%sub\\file.txt",
        "--dpi-desync=fake & calc.exe",
        "--filter-tcp=443 --user=nobody",
        "--wf-tcp=80|calc",
        "--dpi-desync-repeats=%COMSPEC%",
        "--dpi-desync=fake --new --ip-id=\"zero\"x\"",
    ] {
        assert!(parse_bat("x", &wrap(bad)).is_err(), "{bad}");
    }
    assert_eq!(parse_bat("x", "echo hi"), Err(ZapretError::NoWinws));
    assert!(parse_bat("..\\evil", &wrap("--new")).is_err());
}

#[test]
fn not_recommended_mark() {
    let text = format!(":: NOT RECOMMENDED\n{GENERAL}");
    assert!(!parse_bat("general (ALT5)", &text).unwrap().recommended);
}

#[test]
fn sorting_follows_flowseal_menu() {
    let mk = |id: &str, recommended: bool| Strategy {
        id: id.into(),
        title: title(id),
        recommended,
        needs_timestamps: false,
        args: vec![],
    };
    let mut list = vec![
        mk("general (ALT5)", false),
        mk("general (SIMPLE FAKE)", true),
        mk("general (ALT10)", true),
        mk("general", true),
        mk("general (ALT2)", true),
    ];
    sort(&mut list);
    let ids: Vec<&str> = list.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "general",
            "general (ALT2)",
            "general (ALT10)",
            "general (SIMPLE FAKE)",
            "general (ALT5)"
        ]
    );
}

#[test]
fn user_lists_keep_vpn_servers_out() {
    let lists = user_lists(
        &["youtube.com".into()],
        &["bank.ru".into()],
        &["vpn.example.com".into()],
        &[
            "203.0.113.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(lists.general, "youtube.com\n");
    assert_eq!(lists.exclude, "bank.ru\nvpn.example.com\n");
    assert_eq!(lists.ipset_exclude, "203.0.113.10/32\n2001:db8::1/128\n");
    let empty = user_lists(&[], &[], &[], &[]).unwrap();
    assert_eq!(empty.general, "domain.example.abc\n");
    assert_eq!(empty.ipset_exclude, "203.0.113.113/32\n");
    assert!(user_lists(&["evil.com\n--debug".into()], &[], &[], &[]).is_err());
    assert!(user_lists(&[], &["a b".into()], &[], &[]).is_err());
}

#[test]
fn versions() {
    assert!(newer("1.10.4", "1.9.9"));
    assert!(newer("1.10.5", "1.10.4"));
    assert!(!newer("1.10.4", "1.10.4"));
    assert!(!newer("1.10", "1.10.4"));
    assert!(valid_version("1.10.4"));
    assert!(!valid_version("1.10.4; rm"));
    assert!(!valid_version("../1"));
}

#[test]
fn known_binaries_only() {
    assert!(binary_known(
        "winws.exe",
        "AFFB4F69D2EA302A7ABCCD5325D81826E140DDAE014F1E070BC4A6C0DD555188"
    ));
    assert!(!binary_known("winws.exe", &"0".repeat(64)));
    assert!(!binary_known("cygwin1.dll", BINARY_HASHES[0].1));
    assert_eq!(BINARIES.len(), BINARY_HASHES.len());
}

#[test]
fn release_from_github_api() {
    let json = br#"{"tag_name":"1.10.5","assets":[
            {"name":"zapret-discord-youtube-1.10.5.rar","browser_download_url":"https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.5/zapret-discord-youtube-1.10.5.rar","digest":"sha256:aa"},
            {"name":"zapret-discord-youtube-1.10.5.zip","browser_download_url":"https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.5/zapret-discord-youtube-1.10.5.zip","digest":"sha256:291AF673BD0238506F9548E0E94CA0ABF244000F4C9A06960544FB01C5F97B34"}]}"#;
    let r = parse_release(json).unwrap();
    assert_eq!(r.version, "1.10.5");
    assert_eq!(r.sha256, ARCHIVE_SHA256);
    assert!(r.zip_url.ends_with("1.10.5.zip"));
}

#[test]
fn release_from_elsewhere_is_rejected() {
    let foreign = br#"{"tag_name":"1.10.5","assets":[{"name":"z.zip","browser_download_url":"https://evil.example/z.zip","digest":"sha256:291af673bd0238506f9548e0e94ca0abf244000f4c9a06960544fb01c5f97b34"}]}"#;
    assert!(parse_release(foreign).is_err());
    let no_digest = br#"{"tag_name":"1.10.5","assets":[{"name":"zapret-discord-youtube-1.10.5.zip","browser_download_url":"https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.5/zapret-discord-youtube-1.10.5.zip"}]}"#;
    assert!(parse_release(no_digest).is_err());
    let bad_tag = br#"{"tag_name":"../x","assets":[]}"#;
    assert!(parse_release(bad_tag).is_err());
}

#[test]
fn domains() {
    assert!(valid_domain("rr1---sn-abc.googlevideo.com"));
    assert!(!valid_domain("a..b"));
    assert!(!valid_domain("x.com/path"));
    assert!(!valid_domain(""));
}
