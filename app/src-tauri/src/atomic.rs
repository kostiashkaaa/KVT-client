//! Запись файла целиком или никак: настройки, подписки, итоги проверок.

use std::io::{self, Write};
use std::path::Path;

/// Пишет во временный файл `tmp`, сбрасывает его на диск и подменяет `path`.
/// Без `sync_all` при отключении питания NTFS может оставить после переименования
/// пустой файл — и настройки сбросились бы (kill switch — в «выключен»).
pub fn write(path: &Path, tmp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = std::fs::File::create(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn replaces_whole_file() {
        let dir = std::env::temp_dir().join(format!("kvt-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.json");
        let tmp = dir.join("a.json.tmp");
        super::write(&path, &tmp, b"first, longer content").unwrap();
        super::write(&path, &tmp, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(!tmp.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
