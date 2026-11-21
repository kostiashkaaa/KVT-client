//! Выводы: из собранных фактов — шаги от простого к сложному и один итог. Без обращения
//! к сети и состоянию окна, поэтому покрыто тестами.
//!
//! Состав: `basic` — сеть, служба, zapret, подписка; `online` — сервер, интернет без
//! VPN и туннель; `probe` — итоги полной проверки сервера. Стадии идут по очереди:
//! первая же неполадка заканчивает вывод, а шаги копит общий `Out`.

use super::{Diagnosis, Facts, Fix, Step, StepState, Tone};
use kvt_core::i18n::tr;
use kvt_core::trf;

mod basic;
mod online;
mod probe;

/// Накопленные шаги и итоговый вывод.
pub(super) struct Out {
    steps: Vec<Step>,
}

impl Out {
    pub(super) fn new() -> Self {
        Self { steps: Vec::new() }
    }

    pub(super) fn step(
        &mut self,
        title: &'static str,
        state: StepState,
        detail: impl Into<String>,
    ) {
        self.steps.push(Step {
            title,
            state,
            detail: detail.into(),
        });
    }

    /// Завершает вывод, забирая накопленные шаги.
    pub(super) fn finish(
        &mut self,
        tone: Tone,
        title: impl Into<String>,
        detail: impl Into<String>,
        fix: Option<Fix>,
    ) -> Diagnosis {
        Diagnosis {
            tone,
            title: title.into(),
            detail: detail.into(),
            steps: std::mem::take(&mut self.steps),
            fix,
        }
    }
}

pub(super) fn switch(f: &Facts) -> Option<Fix> {
    f.alternative
        .clone()
        .map(|(key, name)| Fix::SwitchServer { key, name })
}

pub(super) fn switch_hint(f: &Facts) -> String {
    match &f.alternative {
        Some((_, name)) => trf!(
            " Можно переключиться на «{name}».",
            " You can switch to “{name}”."
        ),
        None => tr(
            " Рабочей замены в подписке не нашлось — обновите подписку или напишите в поддержку провайдера VPN.",
            " No working replacement in the subscription — update it or contact your VPN provider's support.",
        )
        .into(),
    }
}

pub fn conclude(f: &Facts) -> Diagnosis {
    let mut out = Out::new();
    if let Some(done) = basic::run(f, &mut out) {
        return done;
    }
    if let Some(done) = online::run(f, &mut out) {
        return done;
    }
    probe::finish(f, &mut out)
}
