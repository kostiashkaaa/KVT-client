//! Словарь проверки: шаги, исправления, тон и итог ([`Diagnosis`]), собранные факты ([`Facts`]).

use crate::health::Trace;
use kvt_core::ipc::ServiceStatus;
use kvt_core::probe::Verdict;
use kvt_core::tester::QuickResult;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Ok,
    Warning,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub title: &'static str,
    pub state: StepState,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fix {
    Connect,
    Disconnect,
    SwitchServer {
        key: String,
        name: String,
    },
    RefreshSubscription,
    AddSubscription,
    OpenDnsCheck,
    /// Подобрать стратегию zapret автоматически.
    ZapretAutoselect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnosis {
    pub tone: Tone,
    pub title: String,
    pub detail: String,
    pub steps: Vec<Step>,
    pub fix: Option<Fix>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubFacts {
    pub expired: bool,
    pub exhausted: bool,
}

/// Проба выбранного сервера через тестовое ядро.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeFact {
    Done(Verdict),
    /// NetGovernor не разрешил новое соединение к этому SNI.
    Postponed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub network: bool,
    /// `None` — служба не отвечает.
    pub service: Option<ServiceStatus>,
    /// `None` — подписки нет.
    pub subscription: Option<SubFacts>,
    pub server: Option<String>,
    pub server_tcp: Option<QuickResult>,
    /// Интернет без VPN (проверяется, только когда VPN отключён).
    pub internet: Option<bool>,
    pub probe: Option<ProbeFact>,
    /// Запрос через туннель (только при подключённом VPN).
    pub tunnel: Option<Result<Trace, String>>,
    /// Ключ и название рабочей замены.
    pub alternative: Option<(String, String)>,
    /// Сеть просит войти (проверяется, только если через туннель данные не идут).
    pub captive: bool,
}
