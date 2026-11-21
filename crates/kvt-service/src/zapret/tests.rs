//! Тесты zapret в службе: комплект, подстановки, списки, конфликты.

use super::bundle::{check_bundle, read_version, verify_binaries};
use super::launch::with_separator;
use super::stage::{copy_files, extract, stage};
use kvt_core::zapret;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::*;

fn dev_bundle() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/zapret");
    root.exists().then_some(root)
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kvt-zapret-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn separator_is_added_once() {
    assert_eq!(with_separator(Path::new(r"C:\KVT\bin")), r"C:\KVT\bin\");
    assert_eq!(with_separator(Path::new(r"C:\KVT\bin\")), r"C:\KVT\bin\");
}

#[test]
fn server_ips_and_domains_are_split() {
    let resolved = vec![(
        "Example.com".to_string(),
        vec!["203.0.113.20".parse().unwrap()],
    )];
    let found = server_addresses(
        &[
            "203.0.113.10".into(),
            "bad name;".into(),
            "Example.com".into(),
        ],
        &resolved,
    );
    assert_eq!(found.domains, ["example.com"]);
    assert_eq!(
        found.ips,
        [
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            "203.0.113.20".parse().unwrap()
        ]
    );
}

/// Комплект для разработки (`scripts/fetch-zapret.ps1`): все стратегии и хэши.
#[test]
fn dev_bundle_is_valid() {
    let Some(root) = dev_bundle() else {
        eprintln!("нет комплекта zapret, пропуск");
        return;
    };
    let (ok, rejected) = check_bundle(&root).unwrap();
    assert_eq!(ok.len(), zapret::PREFERRED_ORDER.len());
    assert!(rejected.is_empty());
    assert_eq!(read_version(&root), zapret::FLOWSEAL_VERSION);
}

/// Релиз с подменённым winws.exe и опасной стратегией: в комплект попадают только
/// проверенные программы и стратегии из белого списка.
#[test]
fn staging_keeps_known_binaries_and_safe_strategies() {
    let Some(root) = dev_bundle() else {
        return;
    };
    let release = tmp("release");
    for sub in ["bin", "lists"] {
        std::fs::create_dir_all(release.join(sub)).unwrap();
    }
    copy_files(&root.join("bin"), &release.join("bin"), |_| true, u64::MAX).unwrap();
    copy_files(
        &root.join("lists"),
        &release.join("lists"),
        |_| true,
        u64::MAX,
    )
    .unwrap();
    std::fs::write(release.join("bin").join("winws.exe"), b"not the real winws").unwrap();
    std::fs::copy(
        root.join("strategies").join("general.bat"),
        release.join("general.bat"),
    )
    .unwrap();
    std::fs::write(
        release.join("general (EVIL).bat"),
        "start \"z\" /min \"%BIN%winws.exe\" --debug=@C:\\Windows\\evil.dll\n",
    )
    .unwrap();

    let staging = tmp("staging");
    let binaries_new = stage(&release, &root.join("bin"), &staging, "9.9.9").unwrap();
    assert!(!binaries_new, "подменённый winws.exe не должен приниматься");
    verify_binaries(&staging.join("bin")).unwrap();
    let (ok, _) = check_bundle(&staging).unwrap();
    assert_eq!(ok.len(), 1);
    assert!(!staging
        .join("strategies")
        .join("general (EVIL).bat")
        .exists());
    assert_eq!(read_version(&staging), "9.9.9");
    let _ = std::fs::remove_dir_all(&release);
    let _ = std::fs::remove_dir_all(&staging);
}

/// Системный tar.exe распаковывает zip с каталогом верхнего уровня, как у Flowseal.
#[test]
fn extract_unpacks_zip() {
    let src = tmp("zip-src");
    let inner = src.join("zapret-discord-youtube-9.9.9");
    std::fs::create_dir_all(inner.join("lists")).unwrap();
    std::fs::write(
        inner.join("lists").join("list-general.txt"),
        "discord.com\n",
    )
    .unwrap();
    let archive = tmp("zip").join("r.zip");
    let system =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let ok = std::process::Command::new(system.join("System32").join("tar.exe"))
        .arg("-a")
        .arg("-cf")
        .arg(&archive)
        .arg("-C")
        .arg(&src)
        .arg("zapret-discord-youtube-9.9.9")
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let dest = tmp("zip-out");
    let root = extract(&archive, &dest).unwrap();
    assert!(root.ends_with("zapret-discord-youtube-9.9.9"));
    assert_eq!(
        std::fs::read_to_string(root.join("lists").join("list-general.txt")).unwrap(),
        "discord.com\n"
    );
    for d in [src, dest, archive.parent().unwrap().to_path_buf()] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn broken_bundle_is_reported() {
    let empty = tmp("empty");
    assert!(check_bundle(&empty).is_err());
    assert_eq!(read_version(&empty), "неизвестна");
    let _ = std::fs::remove_dir_all(&empty);
}
