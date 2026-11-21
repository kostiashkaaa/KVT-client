//! Разбор архива с релизом: распаковка и безопасное копирование файлов в каталог комплекта.

use super::ZapretError;
use super::{CREATE_NO_WINDOW, MAX_LIST};
use kvt_core::rulesync::sha256_hex;
use kvt_core::zapret::{self};
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Файлы-«фейки» Flowseal (`*.bin`) — пакеты по несколько сотен байт.
const MAX_FAKE: u64 = 64 * 1024;

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')'))
}

pub(super) fn copy_files(
    from: &Path,
    to: &Path,
    keep: impl Fn(&str) -> bool,
    max: u64,
) -> Result<usize, ZapretError> {
    let mut n = 0;
    let Ok(entries) = std::fs::read_dir(from) else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let meta = entry.metadata().map_err(ZapretError::io)?;
        if meta.is_file() && meta.len() <= max && safe_name(name) && keep(name) {
            std::fs::copy(entry.path(), to.join(name))
                .map_err(|e| ZapretError::Io(format!("{name}: {e}")))?;
            n += 1;
        }
    }
    Ok(n)
}

/// Собирает комплект из распакованного релиза. Стратегии — только прошедшие белый
/// список; исполняемые файлы — новые, если их хэш известен, иначе из `fallback_bin`.
/// Возвращает, обновились ли исполняемые файлы.
pub(super) fn stage(
    release: &Path,
    fallback_bin: &Path,
    staging: &Path,
    version: &str,
) -> Result<bool, ZapretError> {
    for sub in ["bin", "lists", "strategies"] {
        std::fs::create_dir_all(staging.join(sub)).map_err(ZapretError::io)?;
    }
    // Стратегии лежат в корне релиза (так у Flowseal) или в strategies/ (так у KVT).
    for dir in [release.to_path_buf(), release.join("strategies")] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let (Some(id), Some("bat")) = (
                path.file_stem().and_then(|s| s.to_str()),
                path.extension().and_then(|e| e.to_str()),
            ) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if id.starts_with("general") && zapret::parse_bat(id, &text).is_ok() {
                std::fs::write(staging.join("strategies").join(format!("{id}.bat")), text)
                    .map_err(ZapretError::io)?;
            }
        }
    }
    copy_files(
        &release.join("lists"),
        &staging.join("lists"),
        |n| n.ends_with(".txt") || n.ends_with(".backup"),
        MAX_LIST,
    )?;
    copy_files(
        &release.join("bin"),
        &staging.join("bin"),
        |n| n.ends_with(".bin"),
        MAX_FAKE,
    )?;

    let mut all_new = true;
    for name in zapret::BINARIES {
        let new = release.join("bin").join(name);
        let known = std::fs::read(&new).is_ok_and(|b| zapret::binary_known(name, &sha256_hex(&b)));
        let source = if known {
            new
        } else {
            all_new = false;
            fallback_bin.join(name)
        };
        std::fs::copy(&source, staging.join("bin").join(name))
            .map_err(|e| ZapretError::Io(format!("{name}: {e}")))?;
    }
    for license in [
        release.join("LICENSE.txt"),
        fallback_bin.join("..").join("LICENSE.txt"),
    ] {
        if std::fs::copy(&license, staging.join("LICENSE.txt")).is_ok() {
            break;
        }
    }
    std::fs::write(staging.join("VERSION"), version).map_err(ZapretError::io)?;
    Ok(all_new)
}

/// Системный tar.exe (bsdtar) распаковывает zip и не выходит за каталог назначения.
pub(super) fn extract(archive: &Path, dest: &Path) -> Result<PathBuf, ZapretError> {
    let system =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    std::fs::create_dir_all(dest).map_err(ZapretError::io)?;
    let status = std::process::Command::new(system.join("System32").join("tar.exe"))
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| ZapretError::Unpack(e.to_string()))?;
    if !status.success() {
        return Err(ZapretError::UnpackFailed);
    }
    // В архиве Flowseal всё лежит в одном каталоге zapret-discord-youtube-<версия>.
    let dirs: Vec<PathBuf> = std::fs::read_dir(dest)
        .map_err(ZapretError::io)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    Ok(match dirs.as_slice() {
        [only] => only.clone(),
        _ => dest.to_path_buf(),
    })
}
