//! Минимальный DNS (RFC 1035): запрос одной записи и разбор ответа. Этого хватает
//! для проверки резолверов; полноценный DNS делают ядра.

use std::net::Ipv4Addr;
use thiserror::Error;

pub const TYPE_A: u16 = 1;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("{}", crate::i18n::tr("некорректное имя", "invalid name"))]
    BadName,
    #[error("{}", crate::i18n::tr("ответ обрезан", "truncated answer"))]
    Short,
    #[error(
        "{}",
        crate::i18n::tr("ответ на чужой запрос", "answer to another query")
    )]
    IdMismatch,
    #[error("{}", crate::i18n::tr("это не ответ", "not an answer"))]
    NotResponse,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answer {
    pub rcode: u8,
    pub a: Vec<Ipv4Addr>,
}

/// Запрос с флагом рекурсии, класс IN.
pub fn query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, WireError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(WireError::BadName);
    }
    let mut out = Vec::with_capacity(18 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(WireError::BadName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Short)?;
        let s = self.buf.get(self.pos..end).ok_or(WireError::Short)?;
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Имя пропускается, а не разворачивается: ссылки сжатия не читаются,
    /// поэтому зациклиться на них нельзя.
    fn skip_name(&mut self) -> Result<(), WireError> {
        loop {
            let len = self.take(1)?[0];
            match len {
                0 => return Ok(()),
                l if l & 0xC0 == 0xC0 => {
                    self.take(1)?;
                    return Ok(());
                }
                l => {
                    self.take(usize::from(l))?;
                }
            }
        }
    }
}

pub fn parse(msg: &[u8], id: u16) -> Result<Answer, WireError> {
    let mut r = Reader { buf: msg, pos: 0 };
    if r.u16()? != id {
        return Err(WireError::IdMismatch);
    }
    let flags = r.u16()?;
    if flags & 0x8000 == 0 {
        return Err(WireError::NotResponse);
    }
    let questions = r.u16()?;
    let answers = r.u16()?;
    r.take(4)?;
    for _ in 0..questions {
        r.skip_name()?;
        r.take(4)?;
    }
    let mut out = Answer {
        rcode: (flags & 0x000F) as u8,
        a: Vec::new(),
    };
    for _ in 0..answers {
        r.skip_name()?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        r.take(4)?;
        let len = usize::from(r.u16()?);
        let data = r.take(len)?;
        if rtype == TYPE_A && len == 4 {
            out.a
                .push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Ответ, как его присылает резолвер: вопрос, CNAME со сжатым именем и запись A.
    fn sample_response(id: u16) -> Vec<u8> {
        let mut m = query(id, "www.example.com", TYPE_A).unwrap();
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 2;
        // CNAME: имя — ссылка на вопрос (смещение 12).
        m.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 16]);
        m.extend_from_slice(&[0xC0, 16, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        m
    }

    #[test]
    fn query_layout() {
        let q = query(0xBEEF, "ya.ru.", TYPE_A).unwrap();
        assert_eq!(&q[..4], &[0xBE, 0xEF, 0x01, 0x00]);
        assert_eq!(&q[12..], &[2, b'y', b'a', 2, b'r', b'u', 0, 0, 1, 0, 1]);
    }

    #[test]
    fn bad_names_rejected() {
        assert_eq!(query(1, "", TYPE_A), Err(WireError::BadName));
        assert_eq!(query(1, "a..b", TYPE_A), Err(WireError::BadName));
        assert_eq!(query(1, &"a".repeat(64), TYPE_A), Err(WireError::BadName));
        assert_eq!(query(1, "пример.рф", TYPE_A), Err(WireError::BadName));
    }

    #[test]
    fn parses_answer_with_compression() {
        let a = parse(&sample_response(7), 7).unwrap();
        assert_eq!(a.rcode, 0);
        assert_eq!(a.a, [Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn foreign_id_and_query_rejected() {
        assert_eq!(parse(&sample_response(7), 8), Err(WireError::IdMismatch));
        let q = query(9, "ya.ru", TYPE_A).unwrap();
        assert_eq!(parse(&q, 9), Err(WireError::NotResponse));
    }

    #[test]
    fn nxdomain_rcode() {
        let mut m = query(3, "nope.example", TYPE_A).unwrap();
        m[2] = 0x81;
        m[3] = 0x83;
        let a = parse(&m, 3).unwrap();
        assert_eq!(a.rcode, RCODE_NXDOMAIN);
        assert!(a.a.is_empty());
    }

    proptest! {
        /// Ответ приходит из сети: любые байты не должны ронять разбор.
        #[test]
        fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&bytes, 0);
        }

        #[test]
        fn truncated_response_is_error(cut in 0usize..58) {
            let m = sample_response(1);
            prop_assume!(cut < m.len());
            prop_assert!(parse(&m[..cut], 1).is_err());
        }
    }
}
