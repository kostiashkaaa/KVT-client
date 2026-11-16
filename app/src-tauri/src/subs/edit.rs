//! Удаление подписок и серверов, правка ручного ключа.

use super::*;

#[tauri::command]
pub async fn remove_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let before = state.selected();
    with_store(&state, |s| s.remove(&id))?;
    rebuild(&state)?;
    guard_selected(&app, before, Gone::ByUser).await;
    notify(&app);
    Ok(())
}

/// Удаляет один сервер из группы «Добавлено вручную». У подписки по ссылке
/// так нельзя: провайдер вернёт сервер при следующем обновлении.
#[tauri::command]
pub async fn remove_server(
    key: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let entry = state.entry(&key).ok_or(kvt_core::i18n::tr(
        "Этого сервера уже нет в списке.",
        "This server is no longer in the list.",
    ))?;
    let before = state.selected();
    with_store(&state, |store| {
        let sub = store
            .subscriptions
            .iter_mut()
            .find(|s| s.id == entry.sub)
            .ok_or(kvt_core::i18n::tr(
                "Этого сервера уже нет в списке.",
                "This server is no longer in the list.",
            ))?;
        if sub.url.is_some() {
            return Err(kvt_core::i18n::tr(
                "Сервер из подписки по ссылке удалить нельзя — провайдер вернёт его при обновлении.",
                "A server from a link subscription can't be removed — the provider will bring it back on update.",
            )
            .to_string());
        }
        let body = kvt_core::parser::remove_server(sub.body.expose(), &entry.server).ok_or(
            kvt_core::i18n::tr(
                "Не удалось найти этот ключ среди добавленных вручную.",
                "Couldn't find this key among the manually added ones.",
            ),
        )?;
        if parse_subscription_body(&body).servers.is_empty() {
            // Последний ключ — группа больше не нужна.
            let id = sub.id.clone();
            store.remove(&id);
        } else {
            sub.body = Secret::new(body);
            sub.updated_at = now();
        }
        Ok(())
    })??;
    rebuild(&state)?;
    guard_selected(&app, before, Gone::ByUser).await;
    notify(&app);
    Ok(())
}

/// Меняет ключ из группы «Добавлено вручную»: название и, если вставлена, саму
/// ссылку. Пустое название при новой ссылке — название из неё. Если VPN работает
/// через этот ключ и ссылка изменилась, KVT переподключается с новыми параметрами.
/// Возвращает ключ сервера после правки (он меняется вместе с адресом или портом).
#[tauri::command]
pub async fn edit_server(
    key: String,
    name: String,
    link: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let entry = state.entry(&key).ok_or(kvt_core::i18n::tr(
        "Этого сервера уже нет в списке.",
        "This server is no longer in the list.",
    ))?;
    let link = link.map(|l| l.trim().to_owned()).filter(|l| !l.is_empty());
    // Новая ссылка — ровно один сервер (base64 и JSON раскрываются как при добавлении).
    let new_line = match &link {
        Some(raw) => {
            if raw.len() > kvt_core::parser::MAX_URI_LEN * 4 {
                return Err(
                    kvt_core::i18n::tr("Ссылка слишком длинная.", "The link is too long.").into(),
                );
            }
            let normalized = normalize_pasted(raw);
            let content = parse_subscription_body(&normalized);
            if content.servers.len() != 1 {
                return Err(if content.servers.is_empty() {
                    kvt_core::i18n::tr(
                        "В ссылке не нашлось сервера — проверьте, что она скопирована целиком.",
                        "No server found in the link — check that it was copied in full.",
                    )
                    .into()
                } else {
                    kvt_core::i18n::tr(
                        "Вставьте ссылку на один сервер — чтобы добавить несколько, нажмите «Добавить».",
                        "Paste a link to one server — to add several, press “Add”.",
                    )
                    .into()
                });
            }
            normalized
                .lines()
                .find(|l| {
                    matches!(
                        kvt_core::parser::parse_uri(l),
                        Ok(kvt_core::parser::Entry::Server(_))
                    )
                })
                .map(str::to_owned)
                .ok_or(kvt_core::i18n::tr(
                    "В ссылке не нашлось сервера.",
                    "No server found in the link.",
                ))?
        }
        None => String::new(),
    };
    let name = name.trim();
    let changed_link = link.is_some();

    let new_server = with_store(&state, |store| {
        let sub = store
            .subscriptions
            .iter_mut()
            .find(|s| s.id == entry.sub)
            .ok_or(kvt_core::i18n::tr(
                "Этого сервера уже нет в списке.",
                "This server is no longer in the list.",
            ))?;
        if sub.url.is_some() {
            return Err(kvt_core::i18n::tr(
                "Сервер из подписки по ссылке изменить нельзя — провайдер вернёт прежний при обновлении.",
                "A server from a link subscription can't be edited — the provider will restore it on update.",
            )
            .to_string());
        }
        // Без новой ссылки правится название прежней: её строка — из тела группы.
        let base = if changed_link {
            new_line.clone()
        } else {
            find_line(sub.body.expose(), &entry.server).ok_or(kvt_core::i18n::tr(
                "Не удалось найти этот ключ среди добавленных вручную.",
                "Couldn't find this key among the manually added ones.",
            ))?
        };
        let line = if name.is_empty() {
            base
        } else {
            kvt_core::parser::with_name(&base, name).map_err(|e| {
                kvt_core::trf!("Название не подходит: {e}.", "The name doesn't fit: {e}.")
            })?
        };
        let server = match kvt_core::parser::parse_uri(&line) {
            Ok(kvt_core::parser::Entry::Server(s)) => *s,
            _ => {
                return Err(
                    kvt_core::i18n::tr("Ссылка не разобралась.", "Couldn't read the link.")
                        .to_string(),
                )
            }
        };
        let body = kvt_core::parser::replace_server(sub.body.expose(), &entry.server, &line)
            .ok_or(kvt_core::i18n::tr(
                "Не удалось найти этот ключ среди добавленных вручную.",
                "Couldn't find this key among the manually added ones.",
            ))?;
        sub.body = Secret::new(body);
        sub.updated_at = now();
        Ok(server)
    })??;
    rebuild(&state)?;

    let new_key = state
        .servers
        .lock()
        .map_err(lock_err)?
        .iter()
        .find(|e| e.sub == entry.sub && e.server == new_server)
        .map(|e| e.key.clone())
        .ok_or(kvt_core::i18n::tr(
            "Ключ сохранился, но не нашёлся в списке — откройте главную заново.",
            "The key was saved but isn't in the list — reopen the home page.",
        ))?;

    // Выбор и «Недавние» в трее идут за ключом, даже если он сменился.
    let was_selected = {
        let mut choice = state.choice.lock().map_err(lock_err)?;
        let was_selected = choice.server.as_deref() == Some(key.as_str());
        if new_key != key {
            if was_selected {
                choice.server = Some(new_key.clone());
            }
            for k in &mut choice.recent {
                if *k == key {
                    k.clone_from(&new_key);
                }
            }
            crate::save_choice(&app, &choice)?;
        }
        was_selected
    };
    if new_key != key {
        let _ = app.emit(watchdog::CHOICE_EVENT, ());
    }
    if changed_link
        && was_selected
        && matches!(
            query_status().await,
            Ok(Some(ServiceStatus::Connected { .. }))
        )
    {
        state.user_acted();
        let result = crate::connect_current(&app, true).await;
        crate::tray::refresh(&app).await;
        result?;
    } else {
        crate::tray::invalidate(&app);
    }
    notify(&app);
    Ok(new_key)
}

/// Строка-ссылка сервера `target` в теле группы «Добавлено вручную».
pub(super) fn find_line(body: &str, target: &kvt_core::Server) -> Option<String> {
    body.split(kvt_core::parser::CHUNK_SEPARATOR)
        .find_map(|chunk| {
            normalize_pasted(chunk)
                .lines()
                .find(|l| {
                    matches!(
                        kvt_core::parser::parse_uri(l),
                        Ok(kvt_core::parser::Entry::Server(s)) if *s == *target
                    )
                })
                .map(str::to_owned)
        })
}
