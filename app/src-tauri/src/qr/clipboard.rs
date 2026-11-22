//! Две безобидные справки о буфере обмена для `screen`: номер изменения и есть ли
//! в нём картинка. Буфер не открывается и не читается — содержимое окно берёт
//! само, когда пользователь вернулся в KVT.

#![allow(unsafe_code)]

use windows_sys::Win32::System::DataExchange::{
    GetClipboardSequenceNumber, IsClipboardFormatAvailable,
};

/// Стандартные форматы картинки в буфере: Windows сама достраивает недостающие
/// из имеющихся, так что снимок экрана виден хотя бы одним из них.
const CF_BITMAP: u32 = 2;
const CF_DIB: u32 = 8;
const CF_DIBV5: u32 = 17;

/// Номер изменения буфера обмена: растёт при каждой записи в него.
pub fn sequence() -> u32 {
    // SAFETY: функция без параметров, ничего не разыменовывает и буфер не открывает.
    unsafe { GetClipboardSequenceNumber() }
}

/// В буфере сейчас есть картинка (а не только текст или файлы).
pub fn has_image() -> bool {
    [CF_DIB, CF_DIBV5, CF_BITMAP]
        .into_iter()
        // SAFETY: формат — число, буфер не открывается.
        .any(|format| unsafe { IsClipboardFormatAvailable(format) } != 0)
}
