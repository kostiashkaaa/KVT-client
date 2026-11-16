//! «Расширенные» у подписки: клиент, User-Agent, ID устройства, фильтр серверов.

use super::*;

/// «Расширенные» из окна.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionsInput {
    /// Слова через запятую — как ввёл пользователь.
    keep: String,
    drop: String,
    /// `None` — «Авто», иначе ключ из `fetch::PROFILES` или `custom`.
    client: Option<String>,
    user_agent: String,
    hwid: HwidMode,
    /// `None` — не менять, пустая строка — убрать свой ID.
    own_hwid: Option<String>,
}

pub(super) const MAX_USER_AGENT: usize = 200;
pub(super) const MAX_HWID: usize = 128;

pub(super) fn parse_options(input: OptionsInput) -> Result<(SubOptions, OwnHwid), String> {
    let filter = NameFilter::parse(&input.keep, &input.drop)?;
    let custom = input.client.as_deref() == Some(fetch::CUSTOM);
    let user_agent = if custom {
        Some(header_value(&input.user_agent, MAX_USER_AGENT).ok_or(
            kvt_core::i18n::tr("User-Agent пустой, длиннее 200 символов или не латиницей — проверьте строку.", "The User-Agent is empty, longer than 200 characters or not in Latin script — check it."),
        )?)
    } else {
        None
    };
    if let Some(c) = input.client.as_deref() {
        if !custom && !fetch::PROFILES.contains(&c) {
            return Err(kvt_core::i18n::tr(
                "Такого клиента KVT не знает.",
                "KVT doesn't know this client.",
            )
            .into());
        }
    }
    let own = match input.own_hwid.as_deref().map(str::trim) {
        None => OwnHwid::Keep,
        Some("") => OwnHwid::Clear,
        Some(raw) => OwnHwid::Set(header_value(raw, MAX_HWID).ok_or(
            kvt_core::i18n::tr("ID устройства длиннее 128 символов или не латиницей — скопируйте его у провайдера целиком.", "The device ID is longer than 128 characters or not in Latin script — copy it from your provider in full."),
        )?),
    };
    Ok((
        SubOptions {
            filter,
            client: input.client,
            user_agent,
            hwid: input.hwid,
        },
        own,
    ))
}

/// Сохраняет «Расширенные» подписки. Если сменился клиент или ID устройства,
/// подписка по ссылке сразу загружается заново — ошибка загрузки возвращается, но
/// настройки остаются сохранёнными (причина видна у подписки).
#[tauri::command]
pub async fn set_subscription_options(
    id: String,
    options: OptionsInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let (options, own) = parse_options(options)?;
    let before = state.selected();
    let (request_changed, by_url) = with_store(&state, |s| {
        let changed = s.set_options(&id, options, own);
        (changed, s.get(&id).is_some_and(|x| x.url.is_some()))
    })?;
    let request_changed = request_changed.ok_or(kvt_core::i18n::tr(
        "Этой подписки уже нет.",
        "This subscription no longer exists.",
    ))?;
    let result = if request_changed && by_url {
        refresh_one(&state, &id, Refresh::Now).await
    } else {
        Ok(())
    };
    rebuild(&state)?;
    crate::tray::invalidate(&app);
    guard_selected(&app, before, Gone::ByUser).await;
    notify(&app);
    result
}
