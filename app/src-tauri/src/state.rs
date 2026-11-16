//! Состояние приложения (`AppState`): подписки, выбор, замки и счётчики,
//! общие для окна, трея и фоновых задач.

use super::*;

/// Подписки, серверы и ключи живут в Rust; в WebView уходит только
/// `ServerSummary` без паролей, UUID и токенов.
pub(crate) struct AppState {
    /// Сохранённые подписки (загружаются при старте из каталога данных).
    pub(crate) store: Mutex<Option<store::Store>>,
    /// Серверы всех подписок подряд, с ключами.
    pub(crate) servers: Mutex<Vec<catalog::Entry>>,
    /// В `Arc`: полная проверка отдаёт его и тестовому ядру (`CoreProber`).
    pub(crate) governor: Arc<Mutex<NetGovernor>>,
    /// Найденное в других клиентах для переноса (со ссылками — только в Rust).
    pub(crate) migration: Mutex<Vec<kvt_core::migrate::Collected>>,
    /// Подписки в виде для интерфейса: окно может быть закрыто (WebView
    /// выгружен), а при открытии интерфейс восстанавливается отсюда.
    pub(crate) groups: Mutex<Vec<catalog::Group>>,
    /// Идёт полная проверка серверов (одновременно — только одна).
    pub(crate) checking: std::sync::atomic::AtomicBool,
    /// Выбранный сервер, режим и kill switch — ими пользуется и трей.
    pub(crate) choice: Mutex<Choice>,
    /// Итоги полной проверки по ключам серверов.
    pub(crate) outcomes: Mutex<HashMap<String, Outcome>>,
    /// Когда получен каждый итог из `outcomes` (секунды Unix) — см. `outcomes.rs`.
    pub(crate) outcome_times: Mutex<HashMap<String, u64>>,
    /// Последняя проверка DNS: повтор в течение минуты отдаёт её же.
    pub(crate) dns_report: Mutex<Option<(Instant, kvt_core::dns::DnsReport)>>,
    /// Клиент проверки туннеля: держит соединение открытым между проверками.
    pub(crate) health: reqwest::Client,
    /// Сеть, через которую сейчас идёт трафик.
    pub(crate) network: Mutex<Option<netinfo::Network>>,
    /// Идёт автоподбор стратегии zapret и запрошена ли его отмена.
    pub(crate) zapret_picking: std::sync::atomic::AtomicBool,
    pub(crate) zapret_cancel: std::sync::atomic::AtomicBool,
    /// Последняя проверка zapret (ручная, автоматическая или итог подбора).
    pub(crate) zapret_last: Mutex<Option<zapret::CheckRecord>>,
    /// Последний релиз Flowseal и когда его спрашивали.
    pub(crate) zapret_release: Mutex<Option<(Instant, kvt_core::zapret::Release)>>,
    /// Будит автопроверку zapret раньше срока (смена сети).
    pub(crate) zapret_wake: tokio::sync::Notify,
    /// Сообщения для окна, которые появились до его открытия (например, о
    /// повреждённых настройках). Окно забирает их один раз.
    pub(crate) notices: Mutex<Vec<String>>,
    /// Идут ли данные через туннель: `None` — не проверяли или VPN выключен.
    pub(crate) tunnel: Mutex<Option<bool>>,
    /// Будит автопереключение раньше срока (выход из сна, сбой проверки туннеля).
    pub(crate) watchdog_wake: tokio::sync::Notify,
    /// Сервер меняет автоматика (автопереключение или замена сервера, который убрал
    /// провайдер): одновременно — только одна, иначе выбор «скачет» между переборами.
    pub(crate) switching: tokio::sync::Mutex<()>,
    /// Когда автоматика меняла сервер: лимит `watchdog::MAX_INCIDENTS` за полчаса
    /// общий для автопереключения и замены (`watchdog::take_incident`).
    pub(crate) incidents: Mutex<std::collections::VecDeque<Instant>>,
    /// Проверка туннеля сразу после подключения не прошла: `epoch` того подключения.
    /// Автопереключению не нужно подтверждать сбой ещё раз (см. `tunnel::spawn_verify`).
    pub(crate) verify_failed: Mutex<Option<u64>>,
    /// Последний итог «Почему не работает?» — для экспорта диагностики.
    pub(crate) last_diagnosis: Mutex<Option<troubleshoot::Diagnosis>>,
    /// Файлы диагностики, которые пользователь видел в предпросмотре.
    pub(crate) diag_files: Mutex<Vec<diagexport::DiagFile>>,
    /// Последний известный сеанс службы (время и трафик) — для главной и трея.
    pub(crate) session: Mutex<Option<Session>>,
    /// Страница, которую трей попросил открыть до появления окна.
    pub(crate) pending_page: Mutex<Option<String>>,
    /// Растёт с каждым подключением и отключением по воле пользователя (окно, трей,
    /// профиль сети). Автоматика, начатая раньше, видит, что её решение устарело.
    pub(crate) epoch: std::sync::atomic::AtomicU64,
    /// `epoch` последнего отключения по воле пользователя (`user_disconnected`).
    pub(crate) disconnected_at: std::sync::atomic::AtomicU64,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            store: Mutex::default(),
            servers: Mutex::default(),
            governor: Arc::new(Mutex::new(NetGovernor::new(NetPolicy::default()))),
            migration: Mutex::default(),
            groups: Mutex::default(),
            checking: Default::default(),
            choice: Mutex::default(),
            outcomes: Mutex::default(),
            outcome_times: Mutex::default(),
            dns_report: Mutex::default(),
            health: health::client(),
            network: Mutex::default(),
            zapret_picking: Default::default(),
            zapret_cancel: Default::default(),
            zapret_last: Mutex::default(),
            zapret_release: Mutex::default(),
            zapret_wake: tokio::sync::Notify::new(),
            notices: Mutex::default(),
            tunnel: Mutex::default(),
            watchdog_wake: tokio::sync::Notify::new(),
            switching: tokio::sync::Mutex::new(()),
            incidents: Mutex::default(),
            verify_failed: Mutex::default(),
            last_diagnosis: Mutex::default(),
            diag_files: Mutex::default(),
            session: Mutex::default(),
            pending_page: Mutex::default(),
            epoch: Default::default(),
            disconnected_at: Default::default(),
        }
    }
}

impl AppState {
    pub(super) fn entry(&self, key: &str) -> Option<catalog::Entry> {
        self.servers
            .lock()
            .ok()?
            .iter()
            .find(|e| e.key == key)
            .cloned()
    }

    /// Резолвер DoH из настроек туннеля: его первым спрашивают имена серверов при
    /// проверке (`kvt_core::dns::names`).
    pub(crate) fn doh_first(&self) -> String {
        self.choice
            .lock()
            .map(|c| c.dns.remote.clone())
            .unwrap_or_default()
    }

    /// Выбранный сервер; `None` — не выбран или его больше нет в подписках.
    pub(super) fn selected(&self) -> Option<catalog::Entry> {
        let key = self.choice.lock().ok()?.server.clone()?;
        self.entry(&key)
    }

    /// Пользователь подключил, отключил или сменил сервер и режим. Автопереключение
    /// и переподключение после сна, начатые раньше, после этого ничего не делают:
    /// иначе «Отключить» во время проверки туннеля через полминуты включило бы VPN снова.
    pub(crate) fn user_acted(&self) {
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Пользователь отключил VPN (или KVT отключил его за него: сервер исчез, сеть
    /// из профиля «без VPN»). Как `user_acted`, и ещё запоминается, что это было
    /// отключение, — см. `connect_auto`.
    pub(crate) fn user_disconnected(&self) {
        use std::sync::atomic::Ordering;
        let now = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        self.disconnected_at.store(now, Ordering::SeqCst);
    }

    /// После `epoch` пользователь отключился, и это его последнее действие.
    pub(super) fn disconnected_after(&self, epoch: u64) -> bool {
        let at = self
            .disconnected_at
            .load(std::sync::atomic::Ordering::SeqCst);
        at > epoch && at == self.epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::AppState;

    /// Автоматическое подключение отменяется, только если последним действием
    /// пользователя после его начала было «Отключить».
    #[test]
    fn disconnect_after_auto_start_is_detected() {
        let state = AppState::default();
        let start = state.epoch();
        assert!(!state.disconnected_after(start));

        state.user_disconnected();
        assert!(state.disconnected_after(start));

        // Потом пользователь снова что-то сделал (подключился) — это уже не отмена.
        state.user_acted();
        assert!(!state.disconnected_after(start));

        // Отключение до начала автоматики не в счёт.
        state.user_disconnected();
        let later = state.epoch();
        assert!(!state.disconnected_after(later));
    }
}
