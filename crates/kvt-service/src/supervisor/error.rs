//! Ошибки подключения: план, конфиг ядра, ядро и адаптер, kill switch и DNS.
//! Текст — в `Display` (на языке окна); окну уходит строкой в `Response::Failed`
//! (handler.rs).

use crate::dirs::DirError;
use crate::zapret::ZapretError;
use kvt_core::i18n::tr;
use kvt_core::trf;

/// Запуск процесса под присмотром (`spawn_supervised`): ядро или winws.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("{}", trf!("не удалось запустить {}: {}", "couldn't start {}: {}", .what, .cause))]
    Spawn { what: String, cause: String },
    /// Job Object не создан или процесс в него не помещён.
    #[error("job: {0}")]
    Job(String),
    /// Процесс завершился в первые секунды: код выхода и последние строки вывода.
    #[error("{}", trf!(
        "{} завершился сразу после запуска ({}): {}",
        "{} exited right after starting ({}): {}",
        .what, .status, .last
    ))]
    ExitedEarly {
        what: String,
        status: String,
        last: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// План маршрутизации нарушает инварианты (`RoutingPlan::validate`).
    #[error(transparent)]
    Plan(#[from] kvt_core::routing::RoutingError),
    #[error(transparent)]
    Compile(#[from] kvt_core::compile::CompileError),
    #[error("{}", tr(
        "Службе KVT не хватает прав, чтобы создать сетевой адаптер. Переустановите KVT — служба должна работать от имени системы.",
        "The KVT service lacks the rights to create a network adapter. Reinstall KVT — the service must run as SYSTEM.",
    ))]
    NoRightsTun,
    #[error("{}", tr(
        "Службе KVT не хватает прав, чтобы запустить zapret. Переустановите KVT — служба должна работать от имени системы.",
        "The KVT service lacks the rights to start zapret. Reinstall KVT — the service must run as SYSTEM.",
    ))]
    NoRightsZapret,
    #[error(transparent)]
    Dir(#[from] DirError),
    /// HTTP-клиент службы не создался.
    #[error("{0}")]
    Net(String),
    /// Списка маршрутизации нет на диске и он не скачался.
    #[error("{}", trf!(
        "Не удалось загрузить список «{}» с GitHub. Проверьте интернет и подключитесь снова.",
        "Couldn't download the list “{}” from GitHub. Check your internet and connect again.",
        .0
    ))]
    RulesMissing(String),
    /// Конфиг не сериализовался или не записался.
    #[error("{}", trf!("не удалось записать конфиг: {}", "couldn't write the config: {}", .0))]
    Config(String),
    /// DNS мимо туннеля не закрылся — подключение остановлено; внутри — причина.
    #[error("{}", trf!(
        "Не удалось закрыть DNS-запросы мимо VPN, поэтому подключение остановлено. Подключитесь снова; если повторится — сохраните диагностику. ({})",
        "Couldn't block DNS requests outside the VPN, so the connection was stopped. Connect again; if it happens again, save diagnostics. ({})",
        .0
    ))]
    DnsGuard(Box<ConnectError>),
    /// Kill switch не включился — подключение остановлено; внутри — причина.
    #[error("{}", trf!(
        "Не удалось включить kill switch, поэтому подключение остановлено. Подключитесь снова; если повторится — выключите kill switch в настройках и сохраните диагностику. ({})",
        "Couldn't turn on the kill switch, so the connection was stopped. Connect again; if it happens again, turn off the kill switch in settings and save diagnostics. ({})",
        .0
    ))]
    KillSwitch(Box<ConnectError>),
    /// Переподключение не удалось, а прежний kill switch оставлен включённым.
    #[error("{}", trf!(
        "{}. Kill switch держит интернет закрытым — нажмите «Отключить» или подключитесь заново",
        "{}. The kill switch is keeping the internet blocked — press “Disconnect” or connect again",
        .0
    ))]
    KillSwitchKept(Box<ConnectError>),
    #[error("{}", trf!(
        "VPN-ядро остановилось, не создав адаптер: {}",
        "The VPN core stopped without creating an adapter: {}",
        .0
    ))]
    CoreStopped(String),
    #[error(
        "{}",
        tr(
            "интерфейс TUN не появился за 20 с",
            "the TUN interface didn't appear within 20 s"
        )
    )]
    TunTimeout,
    /// Ядро отвергло конфиг при проверке; в скобках — хвост его вывода без секретов.
    #[error("{}", trf!(
        "VPN-ядро не приняло настройки этого сервера — возможно, в ключе неподдерживаемые параметры. Выберите другой сервер или сохраните диагностику. ({})",
        "The VPN core rejected this server's settings — the key may have unsupported parameters. Pick another server or save diagnostics. ({})",
        .0
    ))]
    CoreRejected(String),
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// Фильтры WFP (kill switch, DNS, выход тестовому ядру) не поставились.
    #[error("{0}")]
    Wfp(String),
    #[error(
        "{}",
        tr(
            "Слишком много адресов для проверки серверов за раз",
            "Too many addresses to check servers at once",
        )
    )]
    TooManyProbeAddresses,
    #[error(transparent)]
    Zapret(#[from] ZapretError),
}

impl ConnectError {
    /// Для `map_err` у вызовов WFP.
    pub fn wfp(e: impl std::fmt::Display) -> Self {
        Self::Wfp(e.to_string())
    }
}
