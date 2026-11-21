//! Полная проверка сервера: стадии до неё молчат, вывод делается по её вердикту.

use super::{switch, switch_hint, Out};
use crate::troubleshoot::{Diagnosis, Facts, Fix, ProbeFact, StepState, Tone};
use kvt_core::i18n::tr;
use kvt_core::probe::Verdict;
use kvt_core::trf;

/// Последняя стадия: всегда заканчивает вывод.
pub(super) fn finish(f: &Facts, out: &mut Out) -> Diagnosis {
    match &f.probe {
        Some(ProbeFact::Done(Verdict::Works)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Ok,
                Verdict::Works.message(),
            );
            out.finish(
                Tone::Ok,
                tr("Сервер работает — можно подключаться", "The server works — you can connect"),
                tr(
                    "Через этот сервер данные проходят. Если после подключения сайты не открываются, \
                     запустите проверку ещё раз при включённом VPN.",
                    "Data gets through this server. If sites don't open after connecting, \
                     run the check again with the VPN on.",
                ),
                Some(Fix::Connect),
            )
        }
        Some(ProbeFact::Done(Verdict::Slow)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Warning,
                Verdict::Slow.message(),
            );
            out.finish(
                Tone::Warning,
                tr(
                    "Сервер работает, но медленно",
                    "The server works, but slowly",
                ),
                trf!(
                    "Подключиться можно, но страницы будут открываться с задержкой.{}",
                    "You can connect, but pages will open with a delay.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::Connect)),
            )
        }
        Some(ProbeFact::Done(verdict)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Fail,
                verdict.message(),
            );
            let title = match verdict {
                Verdict::TlsFrozen | Verdict::DataFrozen => tr(
                    "Провайдер блокирует этот сервер",
                    "Your ISP is blocking this server",
                ),
                Verdict::Rejected => tr(
                    "Сервер отклоняет подключение",
                    "The server rejects the connection",
                ),
                Verdict::ConfigError => tr("Сервер не поддерживается", "Server not supported"),
                Verdict::DnsFailed => tr(
                    "Не удаётся найти адрес сервера",
                    "Can't find the server address",
                ),
                _ => tr("Сервер недоступен", "Server unreachable"),
            };
            out.finish(
                Tone::Error,
                title,
                format!("{}.{}", verdict.message(), switch_hint(f)),
                switch(f),
            )
        }
        Some(ProbeFact::Postponed) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Warning,
                tr(
                    "Отложена: к этому серверу недавно подключались",
                    "Postponed: this server was connected to recently",
                ),
            );
            out.finish(
                Tone::Warning,
                tr("Повторите проверку через пару минут", "Repeat the check in a couple of minutes"),
                tr(
                    "Частые подключения к одному серверу заметны провайдеру, поэтому KVT выдерживает \
                     паузу. Сервер отвечает — попробуйте подключиться.",
                    "Frequent connections to one server are noticeable to your ISP, so KVT waits. \
                     The server responds — try connecting.",
                ),
                Some(Fix::Connect),
            )
        }
        None => out.finish(
            Tone::Ok,
            tr("Явных проблем не найдено", "No obvious problems found"),
            tr("Попробуйте подключиться.", "Try connecting."),
            Some(Fix::Connect),
        ),
    }
}
