//! Выбор пользователя (`Choice`): сервер, режим, маршрутизация, DNS, zapret;
//! хранится в settings.json, переносится из прежних версий.

use super::*;

/// Выбор пользователя. Секретов не содержит, поэтому хранится в settings.json
/// в каталоге настроек приложения.
#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct Choice {
    /// Ключ выбранного сервера (`catalog::key`).
    pub(crate) server: Option<String>,
    /// Номер сервера в «основной» подписке — из версий до единого списка.
    /// Читается один раз при запуске и переводится в `server`.
    #[serde(skip_serializing)]
    pub(crate) server_index: Option<i64>,
    pub(crate) mode: Option<String>,
    pub(crate) kill_switch: bool,
    pub(crate) routing: RoutingSettings,
    pub(crate) dns: DnsChoice,
    /// Переключаться на другой сервер, если через текущий перестали идти данные.
    pub(crate) auto_switch: bool,
    pub(crate) networks: Vec<netprofile::NetworkProfile>,
    pub(crate) zapret: zapret::ZapretChoice,
    /// Последние выбранные вручную серверы (для трея). Окно это поле не присылает —
    /// `set_choice` сохраняет прежнее.
    pub(crate) recent: Vec<String>,
    /// Уведомления Windows, пока окно закрыто.
    pub(crate) notifications: bool,
    /// Подключаться к выбранному серверу при запуске KVT.
    pub(crate) connect_on_start: bool,
    /// Узнавать у GitHub, не вышла ли новая версия KVT (`updates`).
    pub(crate) check_updates: bool,
    /// Подсказки первого запуска пройдены или пропущены.
    pub(crate) onboarded: bool,
    /// Автозапуск уже включался при первом запуске установленного KVT: если
    /// пользователь потом его выключил, не включать снова. Окно поле не присылает.
    pub(crate) autostart_offered: bool,
    /// Язык интерфейса. Окно поле не присылает — `set_choice` сохраняет прежнее.
    pub(crate) language: lang::LangChoice,
}

/// Сколько серверов помнит «Недавние» в трее.
pub(super) const RECENT: usize = 5;

impl Choice {
    /// Запоминает ручной выбор сервера для «Недавних».
    pub(super) fn remember(&mut self, key: &str) {
        self.recent.retain(|k| k != key);
        self.recent.insert(0, key.to_owned());
        self.recent.truncate(RECENT);
    }
}

impl Default for Choice {
    fn default() -> Self {
        Self {
            server: None,
            server_index: None,
            mode: None,
            kill_switch: false,
            routing: RoutingSettings::default(),
            dns: DnsChoice::default(),
            auto_switch: true,
            networks: Vec::new(),
            zapret: zapret::ZapretChoice::default(),
            recent: Vec::new(),
            notifications: true,
            connect_on_start: false,
            check_updates: true,
            onboarded: false,
            autostart_offered: false,
            language: lang::LangChoice::Auto,
        }
    }
}

/// Резолверы из `kvt_core::dns::RESOLVERS` (по id).
#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct DnsChoice {
    /// Для сайтов, которые открываются напрямую.
    pub(crate) local: String,
    /// DoH внутри туннеля для всего остального.
    pub(crate) remote: String,
}

impl Default for DnsChoice {
    fn default() -> Self {
        Self {
            local: "yandex".into(),
            remote: "cloudflare".into(),
        }
    }
}

pub(super) fn load_choice(app: &AppHandle) -> settings::Loaded {
    match app.path().app_config_dir() {
        Ok(dir) => settings::load(&dir),
        Err(_) => settings::Loaded {
            choice: Choice::default(),
            notice: None,
        },
    }
}

/// Меняет выбор и сохраняет его, не отпуская блокировку. Окно, трей,
/// автопереключение и профиль сети пишут выбор из разных потоков: если снимок
/// сохранять после блокировки, два писателя могут записать файл в обратном порядке,
/// и после перезапуска вернётся старый выбор. Возвращает новый выбор.
pub(crate) fn update_choice(
    app: &AppHandle,
    f: impl FnOnce(&mut Choice),
) -> Result<Choice, settings::SettingsError> {
    let state = app.state::<AppState>();
    let mut choice = state
        .choice
        .lock()
        .map_err(|_| settings::SettingsError::State)?;
    f(&mut choice);
    save_choice(app, &choice)?;
    Ok(choice.clone())
}

pub(super) fn save_choice(app: &AppHandle, choice: &Choice) -> Result<(), settings::SettingsError> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|_| settings::SettingsError::NoFolder)?;
    settings::save(&dir, choice)
}

/// Выбор из прежних версий: номер сервера в «основной» подписке (до единого списка)
/// и ключи до 0.9.2 (с параметрами TLS) → нынешние ключи.
pub(super) fn migrate_choice(app: &AppHandle, state: &AppState) {
    let (active, legacy) = {
        let Ok(store) = state.store.lock() else {
            return;
        };
        let Some(store) = store.as_ref() else {
            return;
        };
        let entries = state.servers.lock().map(|s| s.clone()).unwrap_or_default();
        (store.active.clone(), catalog::legacy_keys(store, &entries))
    };
    let Ok(mut choice) = state.choice.lock() else {
        return;
    };
    let known = |key: &String| state.entry(key).is_some();
    let mut changed = false;
    if let Some(new) = choice
        .server
        .as_ref()
        .filter(|k| !known(k))
        .and_then(|k| legacy.get(k))
    {
        choice.server = Some(new.clone());
        changed = true;
    }
    for key in &mut choice.recent {
        if let Some(new) = legacy.get(key).filter(|_| !known(key)) {
            *key = new.clone();
            changed = true;
        }
    }
    let Some(index) = choice.server_index.take() else {
        if changed {
            let _ = save_choice(app, &choice);
        }
        return;
    };
    if choice.server.is_none() {
        choice.server = state.servers.lock().ok().and_then(|servers| {
            servers
                .iter()
                .filter(|e| Some(&e.sub) == active.as_ref())
                .nth(usize::try_from(index).ok()?)
                .map(|e| e.key.clone())
        });
    }
    let _ = save_choice(app, &choice);
}
