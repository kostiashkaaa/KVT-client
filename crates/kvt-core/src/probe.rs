//! Классификация результата проверки сервера. Вердикт должен быть понятен
//! человеку и подсказывать, что делать дальше: ждать, менять сервер или транспорт.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Что удалось наблюдать во время пробы (заполняет тестер через ядро).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeObservation {
    pub dns_resolved: bool,
    pub tcp_connected: bool,
    pub tls_handshake_done: bool,
    /// Сколько байт полезных данных пришло до конца или до остановки потока.
    pub bytes_received: u64,
    /// Поток перестал получать данные раньше, чем закончилась загрузка.
    pub stalled: bool,
    pub download_completed: bool,
    pub latency: Option<Duration>,
    /// Ядро не запустилось с конфигурацией этого сервера.
    pub core_error: bool,
    /// Сервер быстро отказал (неверный ключ, сервер не принимает протокол).
    /// В отличие от заморозки ТСПУ, которая выглядит как долгое молчание.
    pub rejected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Works,
    Slow,
    DnsFailed,
    /// Сервер не принимает TCP: IP или подсеть, скорее всего, заблокированы.
    Unreachable,
    /// TCP есть, на ClientHello никто не отвечает — похоже на заморозку по SNI/отпечатку.
    TlsFrozen,
    /// Рукопожатие прошло, но поток встал после ~16–20 КБ — заморозка по объёму.
    DataFrozen,
    /// Сервер отклонил подключение.
    Rejected,
    /// Ядро не приняло конфигурацию сервера.
    ConfigError,
}

impl Verdict {
    /// Заморозка — повод передать SNI в NetGovernor и не повторять попытки.
    pub fn is_freeze(self) -> bool {
        matches!(self, Verdict::TlsFrozen | Verdict::DataFrozen)
    }

    /// Итог для пользователя на текущем языке.
    pub fn message(self) -> &'static str {
        use crate::i18n::tr;
        match self {
            Verdict::Works => tr("Работает", "Works"),
            Verdict::Slow => tr("Работает, но медленно", "Works, but slowly"),
            Verdict::DnsFailed => tr(
                "Не удалось найти адрес сервера — проверьте DNS",
                "Couldn't find the server address — check DNS",
            ),
            Verdict::Unreachable => tr(
                "Сервер недоступен — возможно, заблокирован его IP",
                "Server unreachable — its IP may be blocked",
            ),
            Verdict::TlsFrozen => tr(
                "Провайдер притормозил соединение — подождите или выберите другой сервер",
                "Your ISP stalled the connection — wait or pick another server",
            ),
            Verdict::DataFrozen => tr(
                "Соединение обрывается после первых килобайт — режет DPI",
                "The connection drops after the first kilobytes — DPI is cutting it",
            ),
            Verdict::Rejected => tr(
                "Сервер отклонил подключение — возможно, подписка устарела",
                "The server rejected the connection — the subscription may have expired",
            ),
            Verdict::ConfigError => tr(
                "Этот сервер не поддерживается ядром KVT",
                "This server isn't supported by KVT's core",
            ),
        }
    }
}

/// Диапазон, в котором ТСПУ обычно «замораживает» поток (с запасом).
const FREEZE_WINDOW_BYTES: std::ops::RangeInclusive<u64> = 8 * 1024..=32 * 1024;
const SLOW_LATENCY: Duration = Duration::from_millis(1500);

pub fn classify(o: &ProbeObservation) -> Verdict {
    if !o.dns_resolved {
        return Verdict::DnsFailed;
    }
    if !o.tcp_connected {
        return Verdict::Unreachable;
    }
    if o.core_error {
        return Verdict::ConfigError;
    }
    if o.rejected {
        return Verdict::Rejected;
    }
    if !o.tls_handshake_done {
        return Verdict::TlsFrozen;
    }
    if !o.download_completed && o.stalled && FREEZE_WINDOW_BYTES.contains(&o.bytes_received) {
        return Verdict::DataFrozen;
    }
    if !o.download_completed {
        return Verdict::Unreachable;
    }
    match o.latency {
        Some(l) if l > SLOW_LATENCY => Verdict::Slow,
        _ => Verdict::Works,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> ProbeObservation {
        ProbeObservation {
            dns_resolved: true,
            tcp_connected: true,
            tls_handshake_done: true,
            bytes_received: 200 * 1024,
            stalled: false,
            download_completed: true,
            latency: Some(Duration::from_millis(120)),
            core_error: false,
            rejected: false,
        }
    }

    #[test]
    fn fast_refusal_is_not_a_freeze() {
        let o = ProbeObservation {
            tls_handshake_done: false,
            rejected: true,
            ..ok()
        };
        assert_eq!(classify(&o), Verdict::Rejected);
        assert!(!classify(&o).is_freeze());
    }

    #[test]
    fn healthy() {
        assert_eq!(classify(&ok()), Verdict::Works);
    }

    #[test]
    fn stall_after_16k_is_data_freeze() {
        let o = ProbeObservation {
            bytes_received: 16 * 1024,
            stalled: true,
            download_completed: false,
            ..ok()
        };
        assert_eq!(classify(&o), Verdict::DataFrozen);
        assert!(classify(&o).is_freeze());
    }

    #[test]
    fn no_server_hello_is_tls_freeze() {
        let o = ProbeObservation {
            tls_handshake_done: false,
            ..ok()
        };
        assert_eq!(classify(&o), Verdict::TlsFrozen);
    }

    #[test]
    fn slow_but_working() {
        let o = ProbeObservation {
            latency: Some(Duration::from_secs(2)),
            ..ok()
        };
        assert_eq!(classify(&o), Verdict::Slow);
    }
}
