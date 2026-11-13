//! Проверка сгенерированных конфигов настоящими ядрами: `xray run -test` и
//! `sing-box check`. Нужны ядра (scripts/fetch-cores.ps1) и списки
//! (`kvt-service update-rules --dir target/debug/cores/rules`). Каталог можно
//! задать через KVT_CORES_DIR. Если ядер нет — тест пропускается.

use kvt_core::compile::{compile, compile_probe, CompileInput, DnsPlan, ProbeInbound};
use kvt_core::core_select::CoreKind;
use kvt_core::lists::ITDOG_LISTS;
use kvt_core::parser::{parse_uri, Entry};
use kvt_core::routing::presets::{self, ListMode};
use kvt_core::routing::Action;
use kvt_core::Server;
use std::path::PathBuf;
use std::process::Command;

fn cores_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("KVT_CORES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/cores")
        });
    (dir.join("xray.exe").exists() && dir.join("rules/manifest.json").exists()).then_some(dir)
}

fn server(uri: &str) -> Server {
    match parse_uri(uri).expect("ссылка") {
        Entry::Server(s) => *s,
        Entry::Info(_) => panic!("ожидался сервер"),
    }
}

const REALITY: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?security=reality&sni=www.microsoft.com&fp=firefox&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba8&flow=xtls-rprx-vision#reality";

const SAMPLES: &[(&str, CoreKind)] = &[
    (REALITY, CoreKind::Xray),
    (REALITY, CoreKind::SingBox),
    ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?type=xhttp&security=tls&sni=cdn.example.com&path=%2Fx&fp=edge#xhttp", CoreKind::Xray),
    ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?type=grpc&serviceName=svc&security=tls&fp=edge#grpc", CoreKind::SingBox),
    ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?type=ws&path=%2Fws&host=cdn.example.com&security=tls#ws", CoreKind::Xray),
    ("trojan://secret@tr.example.com:443?sni=tr.example.com#trojan", CoreKind::Xray),
    ("trojan://secret@tr.example.com:443?sni=tr.example.com&type=httpupgrade&path=%2Fu#trojan", CoreKind::SingBox),
    ("ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@198.51.100.7:8388#ss", CoreKind::SingBox),
    ("hy2://secret@hy.example.com:8443?obfs=salamander&obfs-password=x&sni=hy.example.com#hy2", CoreKind::SingBox),
    ("vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MiLCJhZGQiOiJ2bS5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJwYXRoIjoiL3ZtIiwiaG9zdCI6InZtLmV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwic25pIjoidm0uZXhhbXBsZS5jb20ifQ==", CoreKind::Xray),
    ("vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MiLCJhZGQiOiJ2bS5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJwYXRoIjoiL3ZtIiwiaG9zdCI6InZtLmV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwic25pIjoidm0uZXhhbXBsZS5jb20ifQ==", CoreKind::SingBox),
    ("tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@tu.example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=tu.example.com#tuic", CoreKind::SingBox),
    ("anytls://secret@at.example.com:443?sni=at.example.com&fp=firefox#anytls", CoreKind::SingBox),
    ("hy2://secret@hy.example.com:443,20000-30000?sni=hy.example.com#hop", CoreKind::SingBox),
    ("socks5://user:pass@198.51.100.9:1080#socks", CoreKind::SingBox),
    ("http://user:pass@198.51.100.9:8080#http", CoreKind::SingBox),
    ("https://user:pass@px.example.com:8443/?sni=px.example.com#https", CoreKind::SingBox),
    // ECH: готовый ECHConfigList (как у Cloudflare) — в обоих ядрах.
    ("hy2://secret@hy.example.com:443?sni=hy.example.com&ech=AEX%2BDQBBpQAgACB%2FqtKXQOgnyY4kyw6jZ3Zt0ZNy1PtoE6OdBMsyqF4tPQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA%3D#ech", CoreKind::SingBox),
    ("trojan://secret@tr.example.com:443?sni=tr.example.com&ech=AEX%2BDQBBpQAgACB%2FqtKXQOgnyY4kyw6jZ3Zt0ZNy1PtoE6OdBMsyqF4tPQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA%3D#ech", CoreKind::Xray),
    // Настройки провайдера: XHTTP extra с раздельной загрузкой, фрагментация, mux.
    ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@up.example.com:443?type=xhttp&security=tls&sni=up.example.com&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22noGRPCHeader%22%3Atrue%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%2C%22hMaxReusableSecs%22%3A%221800-3000%22%7D%2C%22downloadSettings%22%3A%7B%22address%22%3A%22dl.example.com%22%2C%22port%22%3A443%2C%22network%22%3A%22xhttp%22%2C%22security%22%3A%22reality%22%2C%22realitySettings%22%3A%7B%22serverName%22%3A%22www.microsoft.com%22%2C%22publicKey%22%3A%22Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw%22%2C%22shortId%22%3A%226ba8%22%2C%22fingerprint%22%3A%22firefox%22%7D%2C%22xhttpSettings%22%3A%7B%22path%22%3A%22%2Fd%22%7D%7D%7D&fragment=tlshello,100-200,10-20#xhttp-extra", CoreKind::Xray),
    ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?security=reality&sni=www.microsoft.com&fp=firefox&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba8&flow=xtls-rprx-vision&fragment=1-3,50-100,5&mux=8#reality-fragment", CoreKind::Xray),
    ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?type=ws&path=%2Fws&host=cdn.example.com&security=tls&mux=8&fragment=tlshello,100-200,10-20#ws-mux", CoreKind::Xray),
    // Без fp: sing-box с uTLS Firefox и фрагментацией TLS.
    ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?type=ws&path=%2Fws&host=cdn.example.com&security=tls#ws-default-fp", CoreKind::SingBox),
    ("trojan://secret@tr.example.com:443?sni=tr.example.com&fragment=tlshello,100-200,10-20#trojan-fragment", CoreKind::SingBox),
];

#[test]
fn generated_configs_pass_real_core_checks() {
    let Some(dir) = cores_dir() else {
        eprintln!("ядра или списки не найдены — тест пропущен (см. README, раздел «Разработка»)");
        return;
    };
    let rules = dir.join("rules");
    let rules_str = rules.to_string_lossy().replace('\\', "/");
    let work = std::env::temp_dir().join(format!("kvt-core-check-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("временный каталог");

    let mut failures = Vec::new();
    let mut checked = 0;
    for (i, (uri, core)) in SAMPLES.iter().enumerate() {
        let s = server(uri);

        // Конфиг тестового ядра для полной проверки сервера.
        let hosts: Vec<(String, Vec<std::net::IpAddr>)> = s
            .endpoints()
            .into_iter()
            .map(|name| (name, vec![std::net::IpAddr::from([203, 0, 113, 10])]))
            .collect();
        let probe = ProbeInbound {
            port: 41_000 + i as u16,
            user: "u",
            password: "p",
            // Через раз — с адресом источника, как при подключённом VPN.
            source: (i % 2 == 0).then_some(std::net::Ipv4Addr::new(192, 168, 1, 10)),
            // Адреса имён — как будто найдены через DoH.
            hosts: &hosts,
        };
        let config = compile_probe(*core, &s, &probe).expect("конфиг пробы");
        let path = work.join(format!("{i}-probe.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&config).expect("json")).expect("запись");
        let output = check(&dir, &rules, *core, &path);
        checked += 1;
        if !output.status.success() {
            failures.push(format!(
                "{core:?} {} (проба):\n{}{}",
                s.name,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        for hybrid in [false, true] {
            let mut plan = presets::russia_smart(Action::Proxy, ListMode::Compact)
                .with_servers([s.address.clone()]);
            if hybrid {
                plan.extend(presets::zapret_youtube_discord());
            }
            // Все переключатели сервисов: проверяем, что каждая категория есть в файлах.
            plan.extend(
                ITDOG_LISTS
                    .iter()
                    .filter_map(|l| presets::list_choice(l.id, Action::Proxy)),
            );
            let dns = DnsPlan::default();
            let input = CompileInput {
                server: &s,
                routing: &plan,
                dns: &dns,
                rule_set_dir: &rules_str,
                // Гибрид — заодно без IPv6 (как при отключённом IPv6 в Windows).
                ipv6: !hybrid,
            };
            let compiled = compile(*core, &input).expect("компиляция");
            let path = work.join(format!("{i}-{hybrid}.json"));
            std::fs::write(
                &path,
                serde_json::to_vec_pretty(&compiled.config).expect("json"),
            )
            .expect("запись");

            let output = check(&dir, &rules, *core, &path);
            checked += 1;
            if !output.status.success() {
                failures.push(format!(
                    "{core:?} {} (hybrid={hybrid}):\n{}{}",
                    s.name,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    assert!(
        failures.is_empty(),
        "ядра отвергли конфиги:\n{}",
        failures.join("\n---\n")
    );
    eprintln!("проверено конфигов настоящими ядрами: {checked}");
}

fn check(
    dir: &std::path::Path,
    rules: &std::path::Path,
    core: CoreKind,
    path: &std::path::Path,
) -> std::process::Output {
    match core {
        CoreKind::Xray => Command::new(dir.join("xray.exe"))
            .args(["run", "-test", "-c"])
            .arg(path)
            .env("XRAY_LOCATION_ASSET", rules)
            .output(),
        CoreKind::SingBox => Command::new(dir.join("sing-box.exe"))
            .args(["check", "-c"])
            .arg(path)
            .output(),
    }
    .expect("запуск ядра")
}
