//! Комплект zapret: какой используется (поставленный или обновлённый), версия, стратегии,
//! проверка файлов и хэшей программ.

use crate::dirs::Paths;

use super::system::driver_state;
use super::ZapretError;
use kvt_core::ipc::ZapretInfo;
use kvt_core::rulesync::sha256_hex;
use kvt_core::zapret::{self, Strategy};
use std::path::{Path, PathBuf};

pub(super) fn read_version(bundle: &Path) -> String {
    std::fs::read_to_string(bundle.join("VERSION"))
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| zapret::valid_version(v))
        .unwrap_or_else(|| kvt_core::i18n::tr("неизвестна", "unknown").into())
}

/// Стратегии комплекта (порядок Flowseal) и имена отвергнутых белым списком.
pub(super) fn scan_strategies(bundle: &Path) -> (Vec<Strategy>, Vec<String>) {
    let mut ok = Vec::new();
    let mut rejected = Vec::new();
    let Ok(entries) = std::fs::read_dir(bundle.join("strategies")) else {
        return (ok, rejected);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bat") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        match std::fs::read_to_string(&path)
            .map_err(ZapretError::io)
            .and_then(|t| zapret::parse_bat(id, &t).map_err(ZapretError::io))
        {
            Ok(s) => ok.push(s),
            Err(e) => {
                tracing::warn!(id, %e, "стратегия отвергнута");
                rejected.push(id.to_owned());
            }
        }
    }
    zapret::sort(&mut ok);
    rejected.sort();
    (ok, rejected)
}

pub(super) fn verify_binaries(bin: &Path) -> Result<(), ZapretError> {
    for name in zapret::BINARIES {
        let bytes = std::fs::read(bin.join(name))
            .map_err(|_| ZapretError::FileMissing(name.to_string()))?;
        if !zapret::binary_known(name, &sha256_hex(&bytes)) {
            return Err(ZapretError::FileModified(name.to_string()));
        }
    }
    Ok(())
}

/// Комплект цел: программы проверены, списки на месте, есть хоть одна стратегия.
pub(super) fn check_bundle(bundle: &Path) -> Result<(Vec<Strategy>, Vec<String>), ZapretError> {
    verify_binaries(&bundle.join("bin"))?;
    if !bundle.join("lists").join("list-general.txt").exists() {
        return Err(ZapretError::NoLists);
    }
    let (ok, rejected) = scan_strategies(bundle);
    if ok.is_empty() {
        return Err(ZapretError::NoStrategies);
    }
    Ok((ok, rejected))
}

/// Комплект, которым сейчас пользуется служба: обновлённый, если он цел, иначе из поставки.
pub fn active_bundle(paths: &Paths) -> PathBuf {
    if check_bundle(&paths.zapret_update).is_ok() {
        paths.zapret_update.clone()
    } else {
        paths.zapret.clone()
    }
}

pub fn strategies(paths: &Paths) -> Vec<Strategy> {
    scan_strategies(&active_bundle(paths)).0
}

pub fn info(paths: &Paths) -> ZapretInfo {
    let bundle = active_bundle(paths);
    let checked = check_bundle(&bundle);
    let (strategies, rejected) = match &checked {
        Ok((ok, rejected)) => (ok.len(), rejected.clone()),
        Err(_) => (0, Vec::new()),
    };
    ZapretInfo {
        version: read_version(&bundle),
        bundled_version: read_version(&paths.zapret),
        updated: bundle == paths.zapret_update,
        ok: checked.is_ok(),
        problem: checked.err().map(|e| e.to_string()),
        strategies,
        rejected,
        driver: driver_state(),
    }
}

pub(super) fn data_dir(paths: &Paths) -> PathBuf {
    paths
        .zapret_update
        .parent()
        .map_or_else(|| paths.zapret_update.clone(), Path::to_path_buf)
}
