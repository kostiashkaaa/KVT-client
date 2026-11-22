//! Команда окна «прочитать QR-код с картинки» для панели «+». Картинку в яркости
//! окно готовит само (файл, буфер обмена) и присылает сырыми байтами: сначала
//! ширина и высота (по 4 байта, little-endian), затем по байту на пиксель. Поиск —
//! `kvt_core::qr`, без сети. Текст кода — секрет: возвращается только окну, в
//! журнал и ошибки не попадает. Выделение области экрана — `screen`.

mod clipboard;
// Модуль открыт целиком: `generate_handler!` ищет команду по полному пути.
pub mod screen;

use kvt_core::i18n::tr;
use kvt_core::qr::{self, Outcome};
use tauri::ipc::{InvokeBody, Request};

/// Размеры перед пикселями: ширина и высота, `u32` little-endian.
const HEADER_LEN: usize = 8;

#[tauri::command]
pub async fn qr_decode(request: Request<'_>) -> Result<Outcome, String> {
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err(bad_request());
    };
    let (width, height, gray) = split(bytes).ok_or_else(bad_request)?;
    // Поиск — работа процессора на сотни миллисекунд: не на потоке обработчика.
    let gray = gray.to_vec();
    tokio::task::spawn_blocking(move || qr::decode(width, height, &gray))
        .await
        .map_err(|_| tr("Распознавание прервано", "Recognition was interrupted").to_string())
}

/// Размеры и пиксели из тела запроса; `None` — тело короче заголовка.
fn split(bytes: &[u8]) -> Option<(usize, usize, &[u8])> {
    let (header, gray) = (bytes.get(..HEADER_LEN)?, bytes.get(HEADER_LEN..)?);
    let word = |at: usize| -> Option<usize> {
        let raw: [u8; 4] = header.get(at..at + 4)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(raw)).ok()
    };
    Some((word(0)?, word(4)?, gray))
}

fn bad_request() -> String {
    tr("Не удалось прочитать картинку", "Couldn't read the image").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(width: u32, height: u32, gray: &[u8]) -> Vec<u8> {
        let mut out = width.to_le_bytes().to_vec();
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(gray);
        out
    }

    #[test]
    fn splits_size_and_pixels() {
        let packed = body(3, 2, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(split(&packed), Some((3, 2, &[1u8, 2, 3, 4, 5, 6][..])));
        // Только заголовок — пикселей ноль: проверка размеров — дело `qr::decode`.
        assert_eq!(split(&body(5, 5, &[])), Some((5, 5, &[][..])));
    }

    #[test]
    fn short_body_is_rejected() {
        assert_eq!(split(&[]), None);
        assert_eq!(split(&[1, 2, 3, 4, 5, 6, 7]), None);
    }

    #[test]
    fn size_mismatch_is_left_to_the_decoder() {
        let packed = body(10, 10, &[255; 5]);
        let (width, height, gray) = split(&packed).unwrap_or((0, 0, &[]));
        assert_eq!(qr::decode(width, height, gray), Outcome::BadImage);
    }
}
