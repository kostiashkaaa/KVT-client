//! Каталоги службы: где лежат ядра, списки и временные конфиги, и закрытие каталогов
//! в `ProgramData\KVT` от обычных пользователей.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Paths {
    /// xray.exe, sing-box.exe, wintun.dll — рядом со службой.
    pub cores: PathBuf,
    /// Списки маршрутизации.
    pub rules: PathBuf,
    /// Временные конфиги.
    pub run: PathBuf,
    /// Комплект zapret Flowseal (bin, lists, strategies) — рядом со службой.
    pub zapret: PathBuf,
    /// Рабочие списки winws, включая свои `*-user.txt`.
    pub zapret_lists: PathBuf,
    /// Комплект, обновлённый из релиза Flowseal (кнопка «Обновить»).
    pub zapret_update: PathBuf,
}

/// `C:\ProgramData\KVT`: списки, обновления zapret, журналы.
pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("KVT")
}

impl Paths {
    pub fn standard() -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let exe_dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        let data = data_dir();
        Ok(Self {
            cores: exe_dir.join("cores"),
            zapret: exe_dir.join("zapret"),
            rules: data.join("rules"),
            run: data.join("run"),
            zapret_lists: data.join("zapret"),
            zapret_update: data.join("zapret-bundle"),
        })
    }
}

/// Каталоги, которые уже закрыты в этом запуске службы. Права ставятся раз: в
/// закрытом каталоге пользователь ничего не подменит, а заново — сотни миллисекунд
/// на каждое подключение. Пропал каталог или на его месте ссылка — готовим снова.
#[derive(Default)]
struct Secured(Mutex<HashSet<PathBuf>>);

impl Secured {
    /// Готовить заново не нужно: каталог закрыт раньше и всё ещё каталог.
    fn fresh(&self, dir: &Path, still_dir: bool) -> bool {
        if !still_dir {
            if let Ok(mut s) = self.0.lock() {
                s.remove(dir);
            }
            return false;
        }
        self.0.lock().is_ok_and(|s| s.contains(dir))
    }

    fn remember(&self, dir: &Path) {
        if let Ok(mut s) = self.0.lock() {
            s.insert(dir.to_path_buf());
        }
    }
}

/// Один на процесс намеренно: это знание о файловой системе, а не о подключении, и
/// `secure_dir` зовут журнал, манифест и zapret, у которых своего состояния нет.
static SECURED: std::sync::LazyLock<Secured> = std::sync::LazyLock::new(Secured::default);

/// Каталог не удалось закрыть от обычных пользователей.
#[derive(Debug, thiserror::Error)]
#[error("{}", kvt_core::trf!(
    "не удалось подготовить каталог {}: {}",
    "couldn't prepare the folder {}: {}",
    .dir.display(),
    .cause
))]
pub struct DirError {
    pub dir: PathBuf,
    pub cause: String,
}

/// Каталог только для SYSTEM и администраторов, владелец — администраторы
/// (`win::private_dir`). Внутри `ProgramData\KVT` сначала проверяются родители:
/// пока родитель чужой, в нём можно подложить что угодно.
pub(crate) fn secure_dir(dir: &Path) -> Result<(), DirError> {
    let still_dir = std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir());
    if SECURED.fresh(dir, still_dir) {
        return Ok(());
    }
    let data = data_dir();
    if let Some(parent) = dir.parent().filter(|p| p.starts_with(&data)) {
        secure_dir(parent)?;
    }
    crate::win::private_dir(dir).map_err(|e| DirError {
        dir: dir.to_path_buf(),
        cause: e.to_string(),
    })?;
    SECURED.remember(dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secured_dir_is_prepared_once_until_it_disappears() {
        let s = Secured::default();
        let dir = Path::new(r"C:\ProgramData\KVT\run");
        assert!(!s.fresh(dir, true), "новый каталог готовится");
        s.remember(dir);
        assert!(s.fresh(dir, true), "второй раз — нет");
        assert!(
            !s.fresh(dir, false),
            "пропал или стал ссылкой — готовится снова"
        );
        assert!(!s.fresh(dir, true), "и забыт, пока его не закроют заново");
    }
}
