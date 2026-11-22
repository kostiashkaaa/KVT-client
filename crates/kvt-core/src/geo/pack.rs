//! Упаковка исходной базы DB-IP (CSV `начало,конец,страна`) в компактный формат
//! `geo`. Запускается при обновлении базы (`scripts/update-dbip.ps1`), в окне и
//! службе не нужна.

use super::{FormatError, MAGIC, MAX_COUNTRIES, V6_SHIFT};
use std::net::IpAddr;

/// Страна для адресов, которых в базе нет (дыра между диапазонами).
const UNKNOWN: [u8; 2] = *b"ZZ";

/// Строка CSV не разобралась или база не годится для упаковки.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackError {
    #[error("строка {0}: ожидалось «начало,конец,страна»")]
    Line(usize),
    #[error("строка {0}: не адрес или не двухбуквенный код страны")]
    Value(usize),
    #[error("строка {0}: конец диапазона раньше начала или диапазоны пересекаются")]
    Range(usize),
    #[error("в базе больше 256 стран")]
    TooManyCountries,
    #[error("в базе нет ни одной записи")]
    Empty,
    #[error("запись не поместилась в формат: {0}")]
    Format(#[from] FormatError),
}

/// Сколько записей получилось: для отчёта скрипта обновления.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackStats {
    pub countries: usize,
    pub v4: usize,
    pub v6: usize,
}

/// Диапазон `[start, end]` в числовом виде (IPv4 расширен до 128 бит).
type Span = (u128, u128, [u8; 2]);

/// Собирает базу из текста CSV. Диапазоны сортируются и проверяются на пересечения;
/// дыры между ними закрываются записью «неизвестно» (`ZZ`), соседние диапазоны одной
/// страны сливаются.
pub fn pack(csv: &str) -> Result<(Vec<u8>, PackStats), PackError> {
    let (mut v4, mut v6): (Vec<Span>, Vec<Span>) = (Vec::new(), Vec::new());
    for (n, line) in csv.lines().enumerate() {
        let n = n + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(',');
        let (Some(a), Some(b), Some(c), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PackError::Line(n));
        };
        let (a, b): (IpAddr, IpAddr) = match (a.trim().parse(), b.trim().parse()) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return Err(PackError::Value(n)),
        };
        let code = country_code(c.trim()).ok_or(PackError::Value(n))?;
        match (a, b) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                v4.push((u128::from(u32::from(a)), u128::from(u32::from(b)), code));
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => v6.push((u128::from(a), u128::from(b), code)),
            _ => return Err(PackError::Value(n)),
        }
    }
    if v4.is_empty() && v6.is_empty() {
        return Err(PackError::Empty);
    }

    let mut countries: Vec<[u8; 2]> = v4.iter().chain(&v6).map(|r| r.2).collect();
    countries.push(UNKNOWN);
    countries.sort_unstable();
    countries.dedup();
    if countries.len() > MAX_COUNTRIES {
        return Err(PackError::TooManyCountries);
    }
    let index = |code: [u8; 2]| -> u8 {
        // Страна есть в списке по построению; 0 — недостижимая запасная ветка.
        countries
            .iter()
            .position(|c| *c == code)
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or(0)
    };

    let starts4 = starts(v4, u128::from(u32::MAX), 0)?;
    // IPv6 — по сетям /48: записи, попавшие в одну сеть, сворачиваются в последнюю.
    let starts6 = starts(v6, u128::MAX, V6_SHIFT)?;

    let mut out = MAGIC.to_vec();
    out.extend_from_slice(
        &u16::try_from(countries.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    for code in &countries {
        out.extend_from_slice(code);
    }
    for (table, width) in [(&starts4, 4usize), (&starts6, 6usize)] {
        out.extend_from_slice(&u32::try_from(table.len()).unwrap_or(u32::MAX).to_le_bytes());
        for (start, code) in table {
            out.extend_from_slice(&start.to_le_bytes()[..width]);
            out.push(index(*code));
        }
    }

    // Что получилось, должно разбираться тем же кодом, которым база читается.
    super::CountryDb::parse(&out)?;
    let stats = PackStats {
        countries: countries.len(),
        v4: starts4.len(),
        v6: starts6.len(),
    };
    Ok((out, stats))
}

fn country_code(text: &str) -> Option<[u8; 2]> {
    let bytes: [u8; 2] = text.as_bytes().try_into().ok()?;
    bytes
        .iter()
        .all(u8::is_ascii_alphabetic)
        .then(|| bytes.map(|b| b.to_ascii_uppercase()))
}

/// Начала диапазонов с их странами: по возрастанию, с нуля и без дыр. `max` —
/// последний адрес пространства, `shift` — сколько младших бит отбросить.
fn starts(mut ranges: Vec<Span>, max: u128, shift: u32) -> Result<Vec<(u64, [u8; 2])>, PackError> {
    ranges.sort_unstable_by_key(|r| r.0);
    // Сначала в полном разрешении: дыры закрываем записью «неизвестно».
    let mut full: Vec<(u128, [u8; 2])> = Vec::new();
    // С какого адреса диапазоны ещё не покрыли пространство; `None` — покрыто до конца.
    let mut next: Option<u128> = Some(0);
    for (n, (start, end, code)) in ranges.into_iter().enumerate() {
        let covered_from = next.ok_or(PackError::Range(n + 1))?;
        if end < start || start < covered_from {
            return Err(PackError::Range(n + 1));
        }
        if start > covered_from {
            full.push((covered_from, UNKNOWN));
        }
        full.push((start, code));
        next = end.checked_add(1).filter(|_| end < max);
    }
    // После последнего диапазона до конца пространства — тоже «неизвестно».
    if let Some(rest) = next.filter(|_| !full.is_empty()) {
        full.push((rest, UNKNOWN));
    }

    // Затем с нужной точностью; соседи одной страны сливаются.
    let mut out: Vec<(u64, [u8; 2])> = Vec::new();
    for (start, code) in full {
        let key = u64::try_from(start >> shift).unwrap_or(u64::MAX);
        match out.last_mut() {
            // Тот же блок, что у предыдущей записи, — побеждает последняя.
            Some(last) if last.0 == key => last.1 = code,
            Some(last) if last.1 == code => {}
            _ => out.push((key, code)),
        }
    }
    // Замена в блоке могла оставить подряд две записи одной страны.
    out.dedup_by(|current, previous| previous.1 == current.1);
    Ok(out)
}
