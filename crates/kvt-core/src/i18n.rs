//! Язык текстов для пользователя: русский или английский.
//!
//! Тексты пишутся парой прямо на месте — `tr("Нет ответа", "No response")` или
//! `trf!("Ошибка {code}", "Error {code}")`, — так перевод не потеряется и виден
//! рядом с русским. Язык процесса один: окно ставит его из настроек, служба — из
//! `Hello` каждого запроса окна. Журналы и диагностика остаются по-русски: их
//! читает разработчик.

use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lang {
    #[default]
    Ru,
    En,
}

impl Lang {
    /// Язык по коду интерфейса Windows (`LANGID`): русский для русской,
    /// белорусской и казахской Windows, иначе английский.
    pub fn from_langid(langid: u16) -> Lang {
        const LANG_RUSSIAN: u16 = 0x19;
        const LANG_BELARUSIAN: u16 = 0x23;
        const LANG_KAZAK: u16 = 0x3f;
        match langid & 0x3ff {
            LANG_RUSSIAN | LANG_BELARUSIAN | LANG_KAZAK => Lang::Ru,
            _ => Lang::En,
        }
    }
}

static EN: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Язык только для этого потока — для тестов, которые идут параллельно.
    static OVERRIDE: Cell<Option<Lang>> = const { Cell::new(None) };
}

pub fn set(lang: Lang) {
    EN.store(lang == Lang::En, Ordering::Relaxed);
}

pub fn current() -> Lang {
    if let Some(lang) = OVERRIDE.with(Cell::get) {
        return lang;
    }
    if EN.load(Ordering::Relaxed) {
        Lang::En
    } else {
        Lang::Ru
    }
}

pub fn is_en() -> bool {
    current() == Lang::En
}

/// Текст на текущем языке.
pub fn tr<'a>(ru: &'a str, en: &'a str) -> &'a str {
    if is_en() {
        en
    } else {
        ru
    }
}

/// Пара текстов для постоянных каталогов (`const`): `tr` там не вызвать.
/// В окно уходит строкой на текущем языке.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Text {
    pub ru: &'static str,
    pub en: &'static str,
}

impl Text {
    pub const fn new(ru: &'static str, en: &'static str) -> Self {
        Self { ru, en }
    }

    /// Одинаковый на обоих языках (название сервиса).
    pub const fn same(text: &'static str) -> Self {
        Self { ru: text, en: text }
    }

    pub fn get(&self) -> &'static str {
        tr(self.ru, self.en)
    }
}

impl Serialize for Text {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.get())
    }
}

/// Выполнить `f` с языком `lang` в этом потоке (для тестов).
pub fn with<T>(lang: Lang, f: impl FnOnce() -> T) -> T {
    let prev = OVERRIDE.with(|o| o.replace(Some(lang)));
    let out = f();
    OVERRIDE.with(|o| o.set(prev));
    out
}

/// `format!` на текущем языке: `trf!("Сервер {name}", "Server {name}")`.
#[macro_export]
macro_rules! trf {
    ($ru:literal, $en:literal $(,)?) => {
        if $crate::i18n::is_en() { format!($en) } else { format!($ru) }
    };
    ($ru:literal, $en:literal, $($arg:tt)+) => {
        if $crate::i18n::is_en() { format!($en, $($arg)+) } else { format!($ru, $($arg)+) }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_language() {
        assert_eq!(with(Lang::Ru, || tr("да", "yes")), "да");
        assert_eq!(with(Lang::En, || tr("да", "yes")), "yes");
        let n = 3;
        assert_eq!(with(Lang::En, || trf!("{n} шт.", "{n} pcs")), "3 pcs");
        assert_eq!(with(Lang::Ru, || trf!("{} шт.", "{} pcs", n)), "3 шт.");
    }

    #[test]
    fn windows_language() {
        assert_eq!(Lang::from_langid(0x0419), Lang::Ru);
        assert_eq!(Lang::from_langid(0x0423), Lang::Ru);
        assert_eq!(Lang::from_langid(0x043f), Lang::Ru);
        assert_eq!(Lang::from_langid(0x0409), Lang::En);
        assert_eq!(Lang::from_langid(0x0422), Lang::En);
    }
}
