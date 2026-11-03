//! Обновление списков маршрутизации.
//!
//! - **itdoginfo** — файлы из последнего релиза GitHub; хэш SHA-256 каждого файла
//!   берётся из API релизов. Проверка не чаще раза в сутки.
//! - **runetfreedom** — ветка `release`: `.dat` сверяются с опубликованным
//!   `.sha256sum`, `.srs` — с хэшем git-объекта из API. Проверка раз в неделю.
//!
//! Скачиваются только файлы, нужные текущему плану и ядру, и только если они
//! изменились. Файл заменяется атомарно; при любой ошибке остаётся прежняя версия.

use crate::core_select::CoreKind;
use crate::lists::{RuleSetRef, ITDOG_XRAY_DAT};
use crate::routing::RoutingPlan;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;

pub const ITDOG_RELEASES_API: &str =
    "https://api.github.com/repos/itdoginfo/allow-domains/releases/latest";
const RF_RAW: &str =
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release";
const RF_CONTENTS_API: &str =
    "https://api.github.com/repos/runetfreedom/russia-v2ray-rules-dat/contents";

const ITDOG_EVERY_SECS: u64 = 24 * 60 * 60;
const RF_EVERY_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_META_BYTES: usize = 2 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 160 * 1024 * 1024;
const MANIFEST: &str = "manifest.json";

/// Проверка содержимого скачанного файла.
type HashCheck = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Символы, которые экранируются в пути URL (`!` в `category-ai-!cn` и т. п.).
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.');

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// Файл релиза itdoginfo с таким именем.
    ItdogAsset(String),
    /// `geoip.dat` / `geosite.dat` runetfreedom (рядом лежит `.sha256sum`).
    RfDat(String),
    /// Файл ветки release runetfreedom (путь внутри репозитория).
    RfFile(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleFile {
    /// Имя файла в каталоге правил (без путей).
    pub local: String,
    pub origin: Origin,
}

/// Какие файлы нужны ядру для этого плана.
pub fn required_files(plan: &RoutingPlan, core: CoreKind) -> Vec<RuleFile> {
    let mut out: Vec<RuleFile> = plan
        .rule_sets()
        .into_iter()
        .filter_map(RuleSetRef::parse)
        .map(|set| match (core, &set) {
            (CoreKind::SingBox, RuleSetRef::Itdog(id)) => RuleFile {
                local: set.srs_file(),
                origin: Origin::ItdogAsset(format!("{id}.srs")),
            },
            (CoreKind::SingBox, RuleSetRef::RfSite(name)) => RuleFile {
                local: set.srs_file(),
                origin: Origin::RfFile(format!("sing-box/rule-set-geosite/geosite-{name}.srs")),
            },
            (CoreKind::SingBox, RuleSetRef::RfIp(code)) => RuleFile {
                local: set.srs_file(),
                origin: Origin::RfFile(format!("sing-box/rule-set-geoip/geoip-{code}.srs")),
            },
            (CoreKind::Xray, RuleSetRef::Itdog(_)) => RuleFile {
                local: ITDOG_XRAY_DAT.into(),
                origin: Origin::ItdogAsset("geosite.dat".into()),
            },
            (CoreKind::Xray, rf) => RuleFile {
                local: rf.xray_file().into(),
                origin: Origin::RfDat(rf.xray_file().into()),
            },
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

pub trait Http: Sync {
    /// GET с ограничением размера ответа.
    fn get(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    /// Имя файла → хэш, под которым он был проверен.
    files: BTreeMap<String, String>,
    /// Источник → время последней успешной проверки (unix).
    checked: BTreeMap<String, u64>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub updated: Vec<String>,
    pub unchanged: Vec<String>,
    /// Имя файла и причина. Прежняя версия файла при этом сохраняется.
    pub failed: Vec<(String, String)>,
    /// Источники, которые не проверялись: срок ещё не подошёл.
    pub not_due: Vec<&'static str>,
}

#[derive(Deserialize)]
struct Release {
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
}

#[derive(Deserialize)]
struct Contents {
    sha: String,
    download_url: Option<String>,
}

pub async fn sync<H: Http>(
    http: &H,
    dir: &Path,
    files: &[RuleFile],
    now_unix: u64,
    force: bool,
) -> SyncReport {
    let mut report = SyncReport::default();
    let mut manifest: Manifest = std::fs::read(dir.join(MANIFEST))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    let (itdog, rf): (Vec<&RuleFile>, Vec<&RuleFile>) = files
        .iter()
        .partition(|f| matches!(f.origin, Origin::ItdogAsset(_)));

    if !itdog.is_empty() {
        if is_due(
            &manifest,
            dir,
            &itdog,
            "itdog",
            ITDOG_EVERY_SECS,
            now_unix,
            force,
        ) {
            sync_itdog(http, dir, &itdog, &mut manifest, &mut report, now_unix).await;
        } else {
            report.not_due.push("itdog");
        }
    }
    if !rf.is_empty() {
        if is_due(
            &manifest,
            dir,
            &rf,
            "runetfreedom",
            RF_EVERY_SECS,
            now_unix,
            force,
        ) {
            for file in &rf {
                sync_rf_file(http, dir, file, &mut manifest, &mut report).await;
            }
            if !rf
                .iter()
                .any(|f| report.failed.iter().any(|(n, _)| *n == f.local))
            {
                manifest.checked.insert("runetfreedom".into(), now_unix);
            }
        } else {
            report.not_due.push("runetfreedom");
        }
    }

    if let Ok(bytes) = serde_json::to_vec_pretty(&manifest) {
        let _ = write_atomic(dir, MANIFEST, &bytes);
    }
    report
}

fn is_due(
    m: &Manifest,
    dir: &Path,
    files: &[&RuleFile],
    source: &str,
    every: u64,
    now: u64,
    force: bool,
) -> bool {
    force
        || files.iter().any(|f| !dir.join(&f.local).exists())
        || m.checked
            .get(source)
            .map_or(true, |t| now.saturating_sub(*t) >= every)
}

async fn sync_itdog<H: Http>(
    http: &H,
    dir: &Path,
    files: &[&RuleFile],
    manifest: &mut Manifest,
    report: &mut SyncReport,
    now: u64,
) {
    let release: Release = match http
        .get(ITDOG_RELEASES_API, MAX_META_BYTES)
        .await
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(r) => r,
        Err(e) => {
            for f in files {
                report.failed.push((
                    f.local.clone(),
                    format!("не удалось получить релиз itdoginfo: {e}"),
                ));
            }
            return;
        }
    };
    let mut all_ok = true;
    for file in files {
        let Origin::ItdogAsset(name) = &file.origin else {
            continue;
        };
        let Some(asset) = release.assets.iter().find(|a| &a.name == name) else {
            report
                .failed
                .push((file.local.clone(), "файла нет в релизе".into()));
            all_ok = false;
            continue;
        };
        let Some(expected) = asset
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
        else {
            report
                .failed
                .push((file.local.clone(), "в релизе нет хэша SHA-256".into()));
            all_ok = false;
            continue;
        };
        let tag = format!("sha256:{expected}");
        if manifest.files.get(&file.local) == Some(&tag) && dir.join(&file.local).exists() {
            report.unchanged.push(file.local.clone());
            continue;
        }
        let ok = download_verified(
            http,
            dir,
            file,
            &asset.browser_download_url,
            |b| sha256_hex(b) == expected,
            report,
        )
        .await;
        if ok {
            manifest.files.insert(file.local.clone(), tag);
        }
        all_ok &= ok;
    }
    if all_ok {
        manifest.checked.insert("itdog".into(), now);
    }
}

async fn sync_rf_file<H: Http>(
    http: &H,
    dir: &Path,
    file: &RuleFile,
    manifest: &mut Manifest,
    report: &mut SyncReport,
) {
    let (expected_tag, url, check): (String, String, HashCheck) = match &file.origin {
        Origin::RfDat(name) => {
            let sum = match http.get(&format!("{RF_RAW}/{name}.sha256sum"), 1024).await {
                Ok(b) => String::from_utf8_lossy(&b)
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_lowercase(),
                Err(e) => {
                    report
                        .failed
                        .push((file.local.clone(), format!("нет контрольной суммы: {e}")));
                    return;
                }
            };
            if sum.len() != 64 {
                report
                    .failed
                    .push((file.local.clone(), "некорректная контрольная сумма".into()));
                return;
            }
            let expected = sum.clone();
            (
                format!("sha256:{sum}"),
                format!("{RF_RAW}/{name}"),
                Box::new(move |b| sha256_hex(b) == expected),
            )
        }
        Origin::RfFile(path) => {
            let encoded: Vec<String> = path
                .split('/')
                .map(|s| utf8_percent_encode(s, PATH_SEGMENT).to_string())
                .collect();
            let api = format!("{RF_CONTENTS_API}/{}?ref=release", encoded.join("/"));
            let meta: Contents = match http
                .get(&api, MAX_META_BYTES)
                .await
                .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
            {
                Ok(m) => m,
                Err(e) => {
                    report
                        .failed
                        .push((file.local.clone(), format!("нет сведений о файле: {e}")));
                    return;
                }
            };
            let Some(url) = meta.download_url else {
                report
                    .failed
                    .push((file.local.clone(), "нет ссылки на файл".into()));
                return;
            };
            let expected = meta.sha.to_lowercase();
            (
                format!("git:{expected}"),
                url,
                Box::new(move |b| git_blob_sha1_hex(b) == expected),
            )
        }
        Origin::ItdogAsset(_) => return,
    };
    if manifest.files.get(&file.local) == Some(&expected_tag) && dir.join(&file.local).exists() {
        report.unchanged.push(file.local.clone());
        return;
    }
    if download_verified(http, dir, file, &url, check, report).await {
        manifest.files.insert(file.local.clone(), expected_tag);
    }
}

async fn download_verified<H: Http>(
    http: &H,
    dir: &Path,
    file: &RuleFile,
    url: &str,
    check: impl Fn(&[u8]) -> bool,
    report: &mut SyncReport,
) -> bool {
    let bytes = match http.get(url, MAX_FILE_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            report
                .failed
                .push((file.local.clone(), format!("загрузка не удалась: {e}")));
            return false;
        }
    };
    if bytes.is_empty() || !check(&bytes) {
        report
            .failed
            .push((file.local.clone(), "хэш не совпал — файл отброшен".into()));
        return false;
    }
    match write_atomic(dir, &file.local, &bytes) {
        Ok(()) => {
            report.updated.push(file.local.clone());
            true
        }
        Err(e) => {
            report
                .failed
                .push((file.local.clone(), format!("не удалось записать: {e}")));
            false
        }
    }
}

/// Запись во временный файл и переименование поверх старого.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    if name.contains(['/', '\\']) || name.starts_with('.') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "недопустимое имя файла",
        ));
    }
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dir.join(name))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Хэш git-объекта: SHA-1 от `blob <размер>\0<содержимое>`.
pub fn git_blob_sha1_hex(bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("blob {}\0", bytes.len()).as_bytes());
    h.update(bytes);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::presets::{russia_smart, ListMode};
    use crate::routing::Action;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeHttp {
        routes: HashMap<String, Vec<u8>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeHttp {
        fn with(mut self, url: &str, body: impl Into<Vec<u8>>) -> Self {
            self.routes.insert(url.into(), body.into());
            self
        }
        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }

    impl Http for FakeHttp {
        async fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
            self.calls.lock().unwrap().push(url.into());
            let body = self
                .routes
                .get(url)
                .cloned()
                .ok_or_else(|| "404".to_string())?;
            if body.len() > max_bytes {
                return Err("слишком большой ответ".into());
            }
            Ok(body)
        }
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kvt-rulesync-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn itdog_release(files: &[(&str, &[u8])]) -> String {
        let assets: Vec<String> = files
            .iter()
            .map(|(n, b)| {
                format!(
                    r#"{{"name":"{n}","browser_download_url":"https://dl/{n}","digest":"sha256:{}"}}"#,
                    sha256_hex(b)
                )
            })
            .collect();
        format!(r#"{{"assets":[{}]}}"#, assets.join(","))
    }

    fn itdog_files() -> Vec<RuleFile> {
        vec![RuleFile {
            local: "itdog-youtube.srs".into(),
            origin: Origin::ItdogAsset("youtube.srs".into()),
        }]
    }

    #[test]
    fn required_files_per_core() {
        let plan = russia_smart(Action::Proxy, ListMode::Compact);
        let sb = required_files(&plan, CoreKind::SingBox);
        let names: Vec<&str> = sb.iter().map(|f| f.local.as_str()).collect();
        assert_eq!(
            names,
            [
                "itdog-geoblock.srs",
                "itdog-russia_inside.srs",
                "itdog-russia_outside.srs",
                "rf-geoip-ru.srs"
            ]
        );
        let xr = required_files(&plan, CoreKind::Xray);
        let names: Vec<&str> = xr.iter().map(|f| f.local.as_str()).collect();
        assert_eq!(names, ["geoip.dat", "itdog-geosite.dat"]);
    }

    #[tokio::test]
    async fn downloads_verifies_and_respects_schedule() {
        let dir = tmp_dir("schedule");
        let body: &[u8] = b"srs-v1";
        let http = FakeHttp::default()
            .with(ITDOG_RELEASES_API, itdog_release(&[("youtube.srs", body)]))
            .with("https://dl/youtube.srs", body);
        let files = itdog_files();

        let r = sync(&http, &dir, &files, 1_000, false).await;
        assert_eq!(r.updated, ["itdog-youtube.srs"]);
        assert_eq!(std::fs::read(dir.join("itdog-youtube.srs")).unwrap(), body);
        assert_eq!(http.calls().len(), 2);

        // Через час — ни одного запроса.
        let r = sync(&http, &dir, &files, 1_000 + 3600, false).await;
        assert_eq!(r.not_due, ["itdog"]);
        assert!(http.calls().is_empty());

        // Через сутки — только запрос релиза; файл не изменился и не качается.
        let r = sync(&http, &dir, &files, 1_000 + 25 * 3600, false).await;
        assert_eq!(r.unchanged, ["itdog-youtube.srs"]);
        assert_eq!(http.calls(), [ITDOG_RELEASES_API]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bad_hash_keeps_previous_file() {
        let dir = tmp_dir("badhash");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("itdog-youtube.srs"), b"old").unwrap();
        let http = FakeHttp::default()
            .with(
                ITDOG_RELEASES_API,
                itdog_release(&[("youtube.srs", b"expected")]),
            )
            .with("https://dl/youtube.srs", b"tampered".to_vec());
        let r = sync(&http, &dir, &itdog_files(), 1_000, true).await;
        assert_eq!(r.failed.len(), 1);
        assert!(r.updated.is_empty());
        assert_eq!(
            std::fs::read(dir.join("itdog-youtube.srs")).unwrap(),
            b"old"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn runetfreedom_dat_and_srs_are_verified() {
        let dir = tmp_dir("rf");
        let dat: &[u8] = b"geoip-data";
        let srs: &[u8] = b"srs-data";
        let http = FakeHttp::default()
            .with(&format!("{RF_RAW}/geoip.dat.sha256sum"), format!("{}  geoip.dat\n", sha256_hex(dat)))
            .with(&format!("{RF_RAW}/geoip.dat"), dat)
            .with(
                &format!("{RF_CONTENTS_API}/sing-box/rule-set-geosite/geosite-category-ai-%21cn.srs?ref=release"),
                format!(r#"{{"sha":"{}","download_url":"https://raw/ai.srs"}}"#, git_blob_sha1_hex(srs)),
            )
            .with("https://raw/ai.srs", srs);
        let files = vec![
            RuleFile {
                local: "geoip.dat".into(),
                origin: Origin::RfDat("geoip.dat".into()),
            },
            RuleFile {
                local: "rf-geosite-category-ai-!cn.srs".into(),
                origin: Origin::RfFile(
                    "sing-box/rule-set-geosite/geosite-category-ai-!cn.srs".into(),
                ),
            },
        ];
        let r = sync(&http, &dir, &files, 1_000, false).await;
        assert!(r.failed.is_empty(), "{:?}", r.failed);
        assert_eq!(r.updated.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_file_triggers_check_even_if_not_due() {
        let dir = tmp_dir("missing");
        let body: &[u8] = b"x";
        let http = FakeHttp::default()
            .with(ITDOG_RELEASES_API, itdog_release(&[("youtube.srs", body)]))
            .with("https://dl/youtube.srs", body);
        sync(&http, &dir, &itdog_files(), 1_000, false).await;
        std::fs::remove_file(dir.join("itdog-youtube.srs")).unwrap();
        http.calls();
        let r = sync(&http, &dir, &itdog_files(), 1_100, false).await;
        assert_eq!(r.updated, ["itdog-youtube.srs"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_blob_hash_matches_git() {
        // `printf 'hello\n' | git hash-object --stdin`
        assert_eq!(
            git_blob_sha1_hex(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }
}
