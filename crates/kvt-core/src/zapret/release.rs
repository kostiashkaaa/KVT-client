//! Релизы Flowseal: версия комплекта, адрес и хэш архива, известные хэши программ, разбор
//! ответа GitHub. Сами файлы скачивает и проверяет служба.

use serde::{Deserialize, Serialize};

/// Версия релиза Flowseal, с которым собран KVT (`scripts/fetch-zapret.ps1`).
pub const FLOWSEAL_VERSION: &str = "1.10.4";

/// Архив релиза, с которым собран KVT: им «Переустановить» восстанавливает комплект.
pub const ARCHIVE_SHA256: &str = "291af673bd0238506f9548e0e94ca0abf244000f4c9a06960544fb01c5f97b34";
pub const RELEASES_API: &str =
    "https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest";
const DOWNLOAD_PREFIX: &str =
    "https://github.com/Flowseal/zapret-discord-youtube/releases/download/";

pub fn archive_url(version: &str) -> String {
    format!("{DOWNLOAD_PREFIX}{version}/zapret-discord-youtube-{version}.zip")
}

/// Исполняемые файлы комплекта: они работают от SYSTEM.
pub const BINARIES: &[&str] = &[
    "winws.exe",
    "WinDivert.dll",
    "WinDivert64.sys",
    "cygwin1.dll",
];

/// Проверенные SHA-256 исполняемых файлов. Служба сверяет их перед каждым запуском,
/// а обновление Flowseal принимает новые файлы, только если их хэш есть здесь:
/// новые исполняемые файлы приходят с обновлением KVT, а не из интернета.
pub const BINARY_HASHES: &[(&str, &str)] = &[
    (
        "winws.exe",
        "affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188",
    ),
    (
        "WinDivert.dll",
        "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
    ),
    (
        "WinDivert64.sys",
        "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
    ),
    (
        "cygwin1.dll",
        "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b",
    ),
];

pub fn binary_known(name: &str, sha256: &str) -> bool {
    BINARY_HASHES
        .iter()
        .any(|(n, h)| n.eq_ignore_ascii_case(name) && h.eq_ignore_ascii_case(sha256))
}

/// Версия Flowseal: только цифры и точки (`1.10.4`).
pub fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 20
        && v.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `a` новее `b` (по числам: 1.10.4 новее 1.9.9).
pub fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parts(a) > parts(b)
}

/// Последний релиз Flowseal по ответу API GitHub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub version: String,
    pub zip_url: String,
    pub sha256: String,
}

/// Разбор `releases/latest`. Ссылка — только на релизы Flowseal, хэш — из `digest`
/// (GitHub считает его сам при загрузке файла).
/// Ответ GitHub о релизе Flowseal не подошёл.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("{}", crate::trf!("ответ GitHub: {}", "GitHub response: {}", .0))]
    Json(String),
    #[error("{}", crate::trf!("непонятная версия «{}»", "unrecognized version “{}”", .0))]
    Version(String),
    #[error(
        "{}",
        crate::i18n::tr("в релизе нет архива zip", "the release has no zip archive")
    )]
    NoZip,
    #[error(
        "{}",
        crate::i18n::tr(
            "у архива нет SHA-256 от GitHub",
            "the archive has no SHA-256 from GitHub",
        )
    )]
    NoHash,
}

pub fn parse_release(json: &[u8]) -> Result<Release, ReleaseError> {
    #[derive(Deserialize)]
    struct Asset {
        name: String,
        browser_download_url: String,
        digest: Option<String>,
    }
    #[derive(Deserialize)]
    struct Raw {
        tag_name: String,
        assets: Vec<Asset>,
    }
    let raw: Raw = serde_json::from_slice(json).map_err(|e| ReleaseError::Json(e.to_string()))?;
    let version = raw.tag_name.trim_start_matches('v').to_owned();
    if !valid_version(&version) {
        return Err(ReleaseError::Version(raw.tag_name));
    }
    let expected = archive_url(&version);
    let asset = raw
        .assets
        .into_iter()
        .find(|a| a.name.ends_with(".zip") && a.browser_download_url == expected)
        .ok_or(ReleaseError::NoZip)?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(ReleaseError::NoHash)?
        .to_ascii_lowercase();
    Ok(Release {
        version,
        zip_url: asset.browser_download_url,
        sha256,
    })
}
