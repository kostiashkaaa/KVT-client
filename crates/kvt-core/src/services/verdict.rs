//! Вердикт пробы сервиса: «работает», «медленно», «не работает» и почему.
//!
//! Проба — обычный запрос окна: ответ с любым кодом HTTP значит, что рукопожатие и
//! запрос прошли, а тело читается до `SAMPLE_BYTES`. Порог выбран с запасом выше
//! окна, где ТСПУ обрывает поток (16–20 КБ, см. `probe::classify`): у YouTube и
//! Discord блокировка часто выглядит как замедление, и главная страница отвечает
//! при задушенном видео. Пороги ниже — по опыту, их подбирают на настоящих блокировках.

use std::time::Duration;

/// Сколько тела читаем: дальше окна заморозки (до 32 КБ).
pub const SAMPLE_BYTES: u64 = 64 * 1024;
/// Ответ (заголовки) дольше этого — «медленно».
const SLOW_FIRST_BYTE: Duration = Duration::from_secs(3);
/// Тело `SAMPLE_BYTES` читалось дольше этого — «медленно». Считаем время, а не
/// скорость: первые килобайты идут в «медленном старте» TCP, и скорость по 64 КБ
/// на здоровом канале с большой задержкой выглядела бы низкой.
const SLOW_READ: Duration = Duration::from_secs(3);
/// Тело короче этого скорость чтения не показывает: страница в несколько килобайт
/// «медленной» быть не может.
const MIN_SAMPLE_FOR_READ: u64 = 32 * 1024;

/// Что удалось увидеть у запроса.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sample {
    /// Имя нашлось (ошибка DNS не случилась).
    pub dns_resolved: bool,
    /// Ответ пришёл: соединение, TLS и запрос прошли.
    pub answered: bool,
    /// Время до заголовков ответа.
    pub first_byte: Option<Duration>,
    pub bytes: u64,
    /// Сколько читалось тело.
    pub read: Duration,
    /// Тело кончилось само или набралось `SAMPLE_BYTES`, а не оборвалось и не встало.
    pub complete: bool,
    /// Данные шли, но читать пришлось бросить: на `SAMPLE_BYTES` ушло больше, чем
    /// позволяет окно. Это «очень медленно», а не обрыв.
    pub timed_out: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// Адрес не нашёлся.
    Dns,
    /// Соединение не установилось или рукопожатие не прошло.
    Unreachable,
    /// Ответ начался и оборвался или встал — похоже на заморозку по объёму.
    Cut,
}

impl Cause {
    /// Код для диагностики (без языка): `dns`, `unreachable`, `cut`.
    pub fn code(self) -> &'static str {
        match self {
            Cause::Dns => "dns",
            Cause::Unreachable => "unreachable",
            Cause::Cut => "cut",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Works,
    Slow,
    Down(Cause),
}

impl Health {
    /// Заморозка — повод передать хост в NetGovernor и не повторять попытки.
    pub fn is_freeze(self) -> bool {
        matches!(self, Health::Down(Cause::Cut))
    }

    /// Насколько всё плохо: итог по нескольким адресам — худший из них.
    fn severity(self) -> u8 {
        match self {
            Health::Works => 0,
            Health::Slow => 1,
            Health::Down(_) => 2,
        }
    }

    /// Итог на текущем языке: что случилось (для подсказки под плиткой).
    pub fn message(self) -> &'static str {
        use crate::i18n::tr;
        match self {
            Health::Works => tr("Открывается", "Opens"),
            Health::Slow => tr("Открывается, но медленно", "Opens, but slowly"),
            Health::Down(Cause::Dns) => tr(
                "Не нашёлся адрес — проверьте DNS",
                "Couldn't find the address — check DNS",
            ),
            Health::Down(Cause::Unreachable) => tr(
                "Не открывается: соединение не устанавливается",
                "Doesn't open: the connection can't be made",
            ),
            Health::Down(Cause::Cut) => tr(
                "Соединение обрывается — похоже на блокировку",
                "The connection drops — looks like a block",
            ),
        }
    }
}

pub fn classify(s: &Sample) -> Health {
    if !s.dns_resolved {
        return Health::Down(Cause::Dns);
    }
    if !s.answered {
        return Health::Down(Cause::Unreachable);
    }
    if s.timed_out {
        return Health::Slow;
    }
    if !s.complete {
        return Health::Down(Cause::Cut);
    }
    let slow_start = s.first_byte.is_some_and(|t| t > SLOW_FIRST_BYTE);
    let slow_read = s.bytes >= MIN_SAMPLE_FOR_READ && s.read > SLOW_READ;
    if slow_start || slow_read {
        Health::Slow
    } else {
        Health::Works
    }
}

/// Худший из нескольких результатов (у сервиса бывает больше одного адреса);
/// при равенстве — первый. `None` — результатов нет.
pub fn worst(results: impl IntoIterator<Item = Health>) -> Option<Health> {
    results
        .into_iter()
        .reduce(|a, b| if b.severity() > a.severity() { b } else { a })
}
