//! Данные для окна: серверы и подписки без секретов, снимок выбора, каталоги
//! резолверов и списков.

use super::*;

/// Название сервера для трея и уведомлений, где флаг картинкой не нарисовать:
/// название как в подписке, флаги-эмодзи — кодами стран («RU→EE для wifi»).
pub(crate) fn display_name(s: &Server) -> String {
    kvt_core::flag::plain_name(&s.name)
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerSummary {
    pub(crate) key: String,
    pub(crate) name: String,
    /// Страна по первому флагу в названии (`nl`).
    pub(crate) flag: Option<String>,
    // Адреса, порта и SNI нет: окну они не нужны, а это данные сервера (CLAUDE.md).
    pub(crate) protocol: &'static str,
    pub(crate) transport: &'static str,
    pub(crate) security: &'static str,
    pub(crate) core: CoreKind,
    /// Тот же сервер, что у ключа выше в списке (другое только название).
    pub(crate) same_as: Option<String>,
}

impl ServerSummary {
    pub(super) fn same_as(mut self, key: Option<String>) -> Self {
        self.same_as = key;
        self
    }

    pub(super) fn new(s: &Server, key: &str) -> Self {
        let transport = catalog::transport_kind(&s.transport);
        let security = match &s.security {
            Security::None => "none",
            Security::Tls(_) => "tls",
            Security::Reality(_) => "reality",
        };
        let f = kvt_core::flag::split_flags(&s.name);
        Self {
            key: key.to_owned(),
            name: f.name,
            flag: f.flag,
            protocol: s.protocol.kind(),
            transport,
            security,
            core: select_core(s).core,
            same_as: None,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionInfo {
    pub(crate) title: Option<String>,
    pub(crate) used_bytes: Option<u64>,
    pub(crate) total_bytes: Option<u64>,
    /// Unix-время окончания.
    pub(crate) expire: Option<u64>,
    pub(crate) support_url: Option<String>,
    pub(crate) announce: Option<String>,
}

impl From<&SubscriptionMeta> for SubscriptionInfo {
    fn from(m: &SubscriptionMeta) -> Self {
        Self {
            title: m.title.clone(),
            used_bytes: m.used_bytes(),
            total_bytes: m.total,
            expire: m.expire,
            support_url: m.support_url.clone(),
            announce: m.announce.clone(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Snapshot {
    pub(crate) groups: Vec<catalog::Group>,
    pub(crate) choice: Choice,
}

/// Состояние для интерфейса, открытого заново из трея.
#[tauri::command]
pub(super) fn snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    Ok(Snapshot {
        groups: state.groups.lock().map_err(crate::errors::state)?.clone(),
        choice: state.choice.lock().map_err(crate::errors::state)?.clone(),
    })
}

/// Интерфейс сообщает выбор сервера, режима, kill switch и маршрутизации.
#[tauri::command]
pub(super) fn set_choice(
    mut choice: Choice,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    {
        // Чтение, сохранение и замена — под одной блокировкой: иначе «Недавние» и
        // выбор, которые тем временем поменяли трей или автопереключение, потерялись бы.
        let mut current = state.choice.lock().map_err(crate::errors::state)?;
        choice.recent = current.recent.clone();
        choice.autostart_offered = current.autostart_offered;
        choice.language = current.language;
        if let Some(key) = choice
            .server
            .clone()
            .filter(|k| current.server.as_ref() != Some(k))
        {
            choice.remember(&key);
        }
        save_choice(&app, &choice)?;
        *current = choice;
    }
    tray::invalidate(&app);
    tgproxy::kick(&app);
    Ok(())
}

/// Резолверы для настроек DNS.
#[tauri::command]
pub(super) fn dns_catalog() -> &'static [kvt_core::dns::Resolver] {
    kvt_core::dns::RESOLVERS
}

/// Списки itdoginfo (podkop) для раздела «Маршрутизация».
#[tauri::command]
pub(super) fn list_catalog() -> &'static [kvt_core::lists::ListInfo] {
    kvt_core::lists::ITDOG_LISTS
}

/// Свой сайт для раздела «Маршрутизация»: адрес в том виде, в каком он попадёт в
/// правило (`https://www.Example.com/x` → `example.com`), или понятная ошибка.
#[tauri::command]
pub(super) fn check_route_target(target: String) -> Result<String, String> {
    Ok(presets::custom_display(&target)?.to_owned())
}
