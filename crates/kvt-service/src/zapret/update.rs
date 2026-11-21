//! Обновление комплекта кнопкой «Обновить» и «Переустановить»: загрузка архива, проверка
//! SHA-256, установка и откат.

use crate::dirs::{secure_dir, Paths};

use super::bundle::{active_bundle, check_bundle, data_dir, read_version, scan_strategies};
use super::stage::{extract, stage};
use super::system::remove_driver;
use super::ZapretError;
use crate::net::NetClient;
use kvt_core::ipc::MaintenanceReport;
use kvt_core::rulesync::{sha256_hex, Http};
use kvt_core::zapret::{self};
use std::path::{Path, PathBuf};

const MAX_ARCHIVE: usize = 30 * 1024 * 1024;

/// Скачивает архив и сверяет SHA-256.
async fn fetch_archive(http: &NetClient, url: &str, sha256: &str) -> Result<Vec<u8>, ZapretError> {
    let bytes = http
        .get(url, MAX_ARCHIVE)
        .await
        .map_err(|e| ZapretError::Download(e.to_string()))?;
    if sha256_hex(&bytes) != sha256.to_ascii_lowercase() {
        return Err(ZapretError::HashMismatch);
    }
    Ok(bytes)
}

/// Скачивает архив, сверяет SHA-256 и собирает из него комплект в `zapret-bundle`.
async fn download_bundle(
    paths: &Paths,
    url: &str,
    sha256: &str,
    version: &str,
    fallback_bin: &Path,
) -> Result<bool, ZapretError> {
    let http = NetClient::new(kvt_core::netlog::Purpose::Update).map_err(ZapretError::io)?;
    let bytes = fetch_archive(&http, url, sha256).await?;
    let (paths, version, fallback_bin) = (
        paths.clone(),
        version.to_owned(),
        fallback_bin.to_path_buf(),
    );
    blocking(move || install_bundle(&paths, &bytes, &version, &fallback_bin)).await
}

/// Файловая работа (распаковка, копирование, хэши) и вызовы Windows, которые идут
/// секунды, — в отдельном потоке, а не на потоке обработки команд службы.
pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ZapretError> + Send + 'static,
) -> Result<T, ZapretError> {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or(Err(ZapretError::Interrupted))
}

/// Работа в отдельном потоке оборвалась (паника) — текст для окна.
pub fn interrupted() -> String {
    ZapretError::Interrupted.to_string()
}

/// Собирает комплект из проверенного архива в `zapret-bundle`.
fn install_bundle(
    paths: &Paths,
    bytes: &[u8],
    version: &str,
    fallback_bin: &Path,
) -> Result<bool, ZapretError> {
    // Сначала ProgramData\KVT: удаления ниже идут от SYSTEM и не должны уйти по
    // ссылке, подложенной в чужой каталог.
    secure_dir(&data_dir(paths))?;
    let work = data_dir(paths).join("zapret-work");
    let _ = std::fs::remove_dir_all(&work);
    secure_dir(&work)?;
    let result = (|| {
        let archive = work.join("release.zip");
        std::fs::write(&archive, bytes).map_err(ZapretError::io)?;
        let root = extract(&archive, &work.join("x"))?;
        let staging = data_dir(paths).join("zapret-bundle.new");
        let _ = std::fs::remove_dir_all(&staging);
        secure_dir(&staging)?;
        let binaries = stage(&root, fallback_bin, &staging, version)?;
        if let Err(e) = check_bundle(&staging) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(ZapretError::Rejected(Box::new(e)));
        }
        let _ = std::fs::remove_dir_all(&paths.zapret_update);
        std::fs::rename(&staging, &paths.zapret_update).map_err(ZapretError::io)?;
        Ok(binaries)
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

/// Скачанное обновление Flowseal, которое ещё не установлено.
pub struct Prepared {
    release: zapret::Release,
    archive: Vec<u8>,
    fallback_bin: PathBuf,
}

/// «Обновить», шаг 1 — пока VPN и winws ещё работают: узнать последний релиз и
/// скачать архив (при подключённом VPN — напрямую, при неудаче через туннель).
/// `Err(отчёт)` — обновлять нечего.
pub async fn fetch_update(
    paths: &Paths,
    http: &NetClient,
) -> Result<Result<Prepared, MaintenanceReport>, ZapretError> {
    let body = http
        .get(zapret::RELEASES_API, 1024 * 1024)
        .await
        .map_err(|e| ZapretError::Version(e.to_string()))?;
    let release = zapret::parse_release(&body)?;
    let active = active_bundle(paths);
    let current = read_version(&active);
    if !zapret::newer(&release.version, &current) {
        return Ok(Err(MaintenanceReport {
            version: current.clone(),
            changed: false,
            binaries_updated: false,
            steps: vec![kvt_core::trf!(
                "Установлена последняя версия Flowseal — {current}",
                "The latest Flowseal version is installed — {current}"
            )],
        }));
    }
    let archive = fetch_archive(http, &release.zip_url, &release.sha256).await?;
    Ok(Ok(Prepared {
        release,
        archive,
        fallback_bin: active.join("bin"),
    }))
}

/// «Обновить», шаг 2 — winws уже остановлен: собрать комплект из скачанного архива.
pub fn install_update(paths: &Paths, prepared: Prepared) -> Result<MaintenanceReport, ZapretError> {
    let Prepared {
        release,
        archive,
        fallback_bin,
    } = prepared;
    let binaries = install_bundle(paths, &archive, &release.version, &fallback_bin)?;
    let (strategies, rejected) = scan_strategies(&paths.zapret_update);
    let mut steps = vec![
        kvt_core::trf!(
            "Скачан релиз {} (SHA-256 сверен с GitHub)",
            "Downloaded release {} (SHA-256 checked against GitHub)",
            release.version
        ),
        kvt_core::trf!("Стратегий: {}", "Strategies: {}", strategies.len()),
    ];
    if !rejected.is_empty() {
        steps.push(kvt_core::trf!(
            "Пропущены стратегии с неизвестными флагами: {}",
            "Skipped strategies with unknown flags: {}",
            rejected.join(", ")
        ));
    }
    steps.push(if binaries {
        kvt_core::i18n::tr(
            "winws и WinDivert — проверенные версии",
            "winws and WinDivert are verified versions",
        )
        .into()
    } else {
        kvt_core::i18n::tr(
            "winws и WinDivert в этом релизе новые — KVT оставил проверенные прежние; новые придут с обновлением KVT",
            "winws and WinDivert are new in this release — KVT kept the verified older ones; the new ones will come with a KVT update",
        )
        .into()
    });
    Ok(MaintenanceReport {
        version: release.version,
        changed: true,
        binaries_updated: binaries,
        steps,
    })
}

/// «Переустановить»: комплект из поставки KVT (или заново скачанный по зафиксированному
/// хэшу, если он повреждён), чистые списки и драйвер WinDivert, который поставится заново.
/// `touch_driver` — нет чужих программ, которые сейчас пользуются WinDivert.
pub async fn repair(paths: &Paths, touch_driver: bool) -> Result<MaintenanceReport, ZapretError> {
    let local = paths.clone();
    let (mut steps, mut version, damaged) = blocking(move || {
        let paths = local;
        let mut steps = Vec::new();
        secure_dir(&data_dir(&paths))?;
        if paths.zapret_update.exists() {
            std::fs::remove_dir_all(&paths.zapret_update).map_err(ZapretError::io)?;
            steps.push(
                kvt_core::i18n::tr(
                    "Обновление удалено — используется комплект из KVT",
                    "Update removed — using the bundle shipped with KVT",
                )
                .to_owned(),
            );
        }
        if paths.zapret_lists.exists() {
            let _ = std::fs::remove_dir_all(&paths.zapret_lists);
            steps.push(
                kvt_core::i18n::tr(
                    "Рабочие списки сброшены — создадутся при запуске",
                    "Working lists reset — they'll be recreated on start",
                )
                .to_owned(),
            );
        }
        let version = read_version(&paths.zapret);
        let damaged = match check_bundle(&paths.zapret) {
            Ok(_) => {
                steps.push(kvt_core::trf!(
                    "Файлы комплекта целы (Flowseal {version})",
                    "Bundle files are intact (Flowseal {version})"
                ));
                false
            }
            Err(problem) => {
                steps.push(kvt_core::trf!(
                    "Комплект повреждён: {problem}",
                    "The bundle is damaged: {problem}"
                ));
                true
            }
        };
        Ok((steps, version, damaged))
    })
    .await?;
    if damaged {
        version = zapret::FLOWSEAL_VERSION.to_owned();
        download_bundle(
            paths,
            &zapret::archive_url(&version),
            zapret::ARCHIVE_SHA256,
            &version,
            &paths.zapret.join("bin"),
        )
        .await?;
        steps.push(kvt_core::trf!(
            "Комплект Flowseal {version} скачан заново и проверен",
            "Flowseal bundle {version} re-downloaded and verified"
        ));
    }
    if touch_driver {
        match blocking(|| Ok(remove_driver())).await.and_then(|r| r) {
            Ok(()) => steps.push(
                kvt_core::i18n::tr(
                    "Драйвер WinDivert удалён — установится заново при запуске",
                    "WinDivert driver removed — it'll be reinstalled on start",
                )
                .to_owned(),
            ),
            Err(e) => steps.push(kvt_core::trf!(
                "Драйвер WinDivert не удалось переустановить: {e}",
                "Couldn't reinstall the WinDivert driver: {e}"
            )),
        }
    } else {
        steps.push(
            kvt_core::i18n::tr(
                "Драйвер WinDivert не тронут: им пользуется другая программа",
                "WinDivert driver left alone: another app is using it",
            )
            .to_owned(),
        );
    }
    Ok(MaintenanceReport {
        version,
        changed: true,
        binaries_updated: false,
        steps,
    })
}
