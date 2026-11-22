//! Страна по IP-адресу: локальная база DB-IP Country Lite (CC BY 4.0, атрибуция —
//! `THIRD-PARTY-NOTICES.md` и «О программе»). Нужна серверам, у которых в названии
//! нет флага: по адресу-IP из ссылки узнаём страну без единого сетевого запроса.
//! Доменные адреса не разбираем — для них понадобился бы DNS.
//!
//! База вшита в окно в компактном виде (`pack`), а не в исходном CSV (32 МБ):
//! диапазоны в базе идут подряд без дыр, поэтому хранится только начало каждого и
//! индекс страны. Записи одной ширины, так что поиск — двоичный по самим байтам, без
//! распаковки и без лишней памяти. Разбор и поиск не паникуют (в релизе паника —
//! `abort`): любая ошибка формата — «страны нет».
//!
//! Формат (числа — little-endian):
//!
//! ```text
//! "KVTGEO\0\x01"
//! u16 n, затем n кодов стран по 2 буквы
//! u32 n4, затем n4 записей по 5 байт: u32 начало диапазона IPv4, u8 индекс страны
//! u32 n6, затем n6 записей по 7 байт: u48 начало диапазона IPv6 (старшие 48 бит —
//!         сеть /48), u8 индекс страны
//! ```

mod pack;
#[cfg(test)]
mod tests;

pub use pack::{pack, PackError, PackStats};

use std::net::IpAddr;

const MAGIC: [u8; 8] = *b"KVTGEO\0\x01";
const V4_WIDTH: usize = 5;
const V6_WIDTH: usize = 7;
/// IPv6 храним с точностью до сети /48: на ней строит свои диапазоны сама база.
const V6_SHIFT: u32 = 80;
/// Индекс страны — один байт.
const MAX_COUNTRIES: usize = 256;

/// База не разобралась: файл не тот, обрезан или испорчен.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("не база стран KVT (неверная сигнатура)")]
    Magic,
    #[error("база стран обрезана")]
    Truncated,
    #[error("в базе стран лишние данные в конце")]
    Trailing,
    #[error("в базе стран нарушен порядок или индекс страны")]
    Corrupt,
}

/// Разобранная база: ссылки на вшитые байты, ничего не копируется.
#[derive(Debug, Clone, Copy)]
pub struct CountryDb<'a> {
    countries: &'a [u8],
    v4: &'a [u8],
    v6: &'a [u8],
}

impl<'a> CountryDb<'a> {
    /// Разбирает и проверяет базу целиком: порядок диапазонов, индексы стран, коды.
    /// Проверка идёт по каждой записи (около 730 тысяч, миллисекунды) — после неё
    /// поиск не встретит неверных данных.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FormatError> {
        let db = Self::parse_layout(bytes)?;
        db.check()?;
        Ok(db)
    }

    /// Только раскладка по секциям, без проверки записей.
    fn parse_layout(bytes: &'a [u8]) -> Result<Self, FormatError> {
        let rest = bytes.strip_prefix(&MAGIC).ok_or(FormatError::Magic)?;
        let (count, rest) = take(rest, 2)?;
        let count = usize::from(u16::from_le_bytes([count[0], count[1]]));
        let (countries, rest) = take(rest, count.checked_mul(2).ok_or(FormatError::Truncated)?)?;
        let (v4, rest) = section(rest, V4_WIDTH)?;
        let (v6, rest) = section(rest, V6_WIDTH)?;
        if !rest.is_empty() {
            return Err(FormatError::Trailing);
        }
        Ok(Self { countries, v4, v6 })
    }

    fn check(&self) -> Result<(), FormatError> {
        let n = self.countries.len() / 2;
        if n > MAX_COUNTRIES
            || self
                .countries
                .iter()
                .any(|b| !b.is_ascii_uppercase() && !b.is_ascii_digit())
        {
            return Err(FormatError::Corrupt);
        }
        for (table, width) in [(self.v4, V4_WIDTH), (self.v6, V6_WIDTH)] {
            let mut prev: Option<u64> = None;
            for record in table.chunks_exact(width) {
                let start = start_of(record);
                let index = record.last().copied().map_or(usize::MAX, usize::from);
                // Диапазоны идут по возрастанию, и первый начинается с нуля: иначе
                // часть адресов никуда бы не попала.
                let ordered = match prev {
                    None => start == 0,
                    Some(p) => start > p,
                };
                if !ordered || index >= n {
                    return Err(FormatError::Corrupt);
                }
                prev = Some(start);
            }
        }
        Ok(())
    }

    /// Страна адреса: код из двух букв (`b"NL"`). `None` — базы по такому адресу
    /// нет. Код `ZZ` у самой базы значит «не распределён или частный адрес».
    pub fn country(&self, ip: IpAddr) -> Option<[u8; 2]> {
        let index = match ip.to_canonical() {
            IpAddr::V4(a) => find(self.v4, V4_WIDTH, u64::from(u32::from(a))),
            IpAddr::V6(a) => find(self.v6, V6_WIDTH, (u128::from(a) >> V6_SHIFT) as u64),
        }?;
        let at = usize::from(index) * 2;
        self.countries.get(at..at + 2)?.try_into().ok()
    }

    /// Сколько диапазонов IPv4 и IPv6 в базе.
    pub fn len(&self) -> (usize, usize) {
        (self.v4.len() / V4_WIDTH, self.v6.len() / V6_WIDTH)
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Отрезает `n` байт от начала.
fn take(bytes: &[u8], n: usize) -> Result<(&[u8], &[u8]), FormatError> {
    bytes.split_at_checked(n).ok_or(FormatError::Truncated)
}

/// Секция записей: число записей (u32), затем сами записи по `width` байт.
fn section(bytes: &[u8], width: usize) -> Result<(&[u8], &[u8]), FormatError> {
    let (count, rest) = take(bytes, 4)?;
    let count = u32::from_le_bytes([count[0], count[1], count[2], count[3]]);
    let len = usize::try_from(count)
        .ok()
        .and_then(|c| c.checked_mul(width))
        .ok_or(FormatError::Truncated)?;
    take(rest, len)
}

/// Начало диапазона в записи: все байты, кроме последнего (индекса страны).
fn start_of(record: &[u8]) -> u64 {
    record
        .iter()
        .take(record.len().saturating_sub(1))
        .enumerate()
        .fold(0, |acc, (i, b)| acc | (u64::from(*b) << (8 * i)))
}

/// Индекс страны той записи, чьё начало — наибольшее из не превосходящих `key`.
fn find(table: &[u8], width: usize, key: u64) -> Option<u8> {
    let count = table.len() / width;
    // Первая запись, начало которой больше `key`.
    let (mut lo, mut hi) = (0, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if start_of(table.get(mid * width..(mid + 1) * width)?) <= key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let record = table.get(lo.checked_sub(1)? * width..lo * width)?;
    record.last().copied()
}
