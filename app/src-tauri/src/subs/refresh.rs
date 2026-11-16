//! Обновление подписок: по кнопке, всех разом и по расписанию в фоне.

use super::*;

/// Как обновляется подписка.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Refresh {
    /// Кнопка «Обновить» у одной подписки: сразу и целиком — пользователь ждёт
    /// свежий трафик и срок, а не «не изменилась».
    Now,
    /// «Обновить все» и трей: подождать очереди к серверу подписки (несколько
    /// подписок одного провайдера подряд), но тоже целиком.
    Batch,
    /// По расписанию: в очереди и с вопросом «изменилась ли» (ETag / Last-Modified).
    Scheduled,
}

/// Обновляет одну подписку по ссылке. Ошибка не трогает сохранённую версию, а
/// запоминается у подписки.
pub(super) async fn refresh_one(state: &AppState, id: &str, how: Refresh) -> Result<(), SubsError> {
    let (url, plan) = {
        let guard = state.store.lock().map_err(lock_err)?;
        let url = guard
            .as_ref()
            .and_then(|s| s.get(id))
            .and_then(|s| s.url.clone())
            .ok_or(SubsError::NoLink)?;
        drop(guard);
        let mut plan = Plan::of(state, |s| s.id == id)?;
        // Метки — только по расписанию и у непустого тела: подписка, добавленная
        // без ответа провайдера, должна загрузиться целиком.
        if how != Refresh::Scheduled || plan.empty_body {
            plan.validators = None;
        }
        (url, plan)
    };
    let url = fetch::validate_url(url.expose())?;
    let result = async {
        let host = url.host_str().unwrap_or_default();
        if how == Refresh::Now {
            fetch::acquire(&state.governor, host)?;
        } else {
            fetch::acquire_patiently(&state.governor, host, BATCH_WAIT).await?;
        }
        let request = plan.hints(host, plan.agent.as_deref())?;
        let loaded = fetch::load(&url, &request.hints()).await?;
        if let fetch::Loaded::Fresh(fetched) = &loaded {
            ensure_servers(&fetched.body)?;
        }
        Ok::<_, SubsError>(loaded)
    }
    .await;
    match result {
        Ok(fetch::Loaded::Fresh(fetched)) => {
            with_store(state, |s| {
                s.update(id, fetched.body, fetched.meta, now());
                s.set_source(id, fetched.agent, fetched.validators, fetched.hwid_sent);
            })?;
            Ok(())
        }
        Ok(fetch::Loaded::NotModified(meta)) => {
            with_store(state, |s| s.not_modified(id, meta, now()))?;
            Ok(())
        }
        Err(e) => {
            with_store(state, |s| s.postpone(id, now(), Some(&e.to_string())))?;
            Err(e)
        }
    }
}

/// Как спрашивать провайдера: настройки подписки и что запомнено с прошлого раза.
/// Собирается под блокировкой хранилища, используется уже без неё.
#[derive(Default)]
pub(super) struct Plan {
    options: SubOptions,
    own_hwid: Option<Secret>,
    hwid_asked: bool,
    agent: Option<String>,
    validators: Option<Validators>,
    empty_body: bool,
    dir: Option<PathBuf>,
}

/// Готовые значения для `fetch::Hints` (они только заимствуют).
pub(super) struct Request<'a> {
    plan: &'a Plan,
    agent: Option<&'a str>,
    hwid: Option<String>,
}

impl Plan {
    /// Настройки подписки, подходящей под `find`; нет такой — по умолчанию.
    pub(super) fn of(
        state: &AppState,
        find: impl Fn(&Subscription) -> bool,
    ) -> Result<Plan, SubsError> {
        let guard = state.store.lock().map_err(lock_err)?;
        let Some(store) = guard.as_ref() else {
            return Ok(Plan::default());
        };
        let dir = store.dir().map(PathBuf::from);
        Ok(match store.subscriptions.iter().find(|s| find(s)) {
            Some(s) => Plan {
                options: s.options.clone(),
                own_hwid: s.own_hwid.clone(),
                hwid_asked: s.hwid_asked,
                agent: s.agent.clone(),
                validators: s.validators.clone(),
                empty_body: s.body.expose().is_empty(),
                dir,
            },
            None => Plan {
                dir,
                ..Plan::default()
            },
        })
    }

    /// ID устройства для провайдера `host`: свой от провайдера или производный от
    /// секрета установки (`device`).
    pub(super) fn hints<'a>(
        &'a self,
        host: &str,
        agent: Option<&'a str>,
    ) -> Result<Request<'a>, SubsError> {
        let mode = self.options.hwid;
        let hwid = if mode == HwidMode::Never {
            None
        } else if let Some(own) = &self.own_hwid {
            Some(own.expose().to_owned())
        } else {
            match self.dir.as_deref().map(|d| crate::device::hwid(d, host)) {
                Some(Ok(id)) => Some(id),
                Some(Err(e)) if mode == HwidMode::Always => {
                    return Err(SubsError::Device(crate::errors::io(
                        kvt_core::i18n::tr(
                            "Не удалось прочитать ID устройства",
                            "Couldn't read the device ID",
                        ),
                        &e,
                    )))
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "ID устройства недоступен");
                    None
                }
                None => None,
            }
        };
        Ok(Request {
            plan: self,
            agent,
            hwid,
        })
    }
}

impl Request<'_> {
    pub(super) fn hints(&self) -> fetch::Hints<'_> {
        let options = &self.plan.options;
        let client = match (options.client.as_deref(), options.user_agent.as_deref()) {
            (Some(fetch::CUSTOM), Some(agent)) => fetch::Client::Custom(agent),
            (Some(fetch::CUSTOM), None) | (None, _) => fetch::Client::Auto,
            (Some(key), _) => fetch::Client::Profile(key),
        };
        let hwid = match (&self.hwid, options.hwid) {
            (None, _) | (_, HwidMode::Never) => fetch::Hwid::Off,
            (Some(id), HwidMode::Always) => fetch::Hwid::Send(id),
            (Some(id), HwidMode::Auto) if self.plan.hwid_asked => fetch::Hwid::Send(id),
            (Some(id), HwidMode::Auto) => fetch::Hwid::OnRequest(id),
        };
        fetch::Hints {
            client,
            agent: self.agent,
            validators: self.plan.validators.as_ref(),
            hwid,
        }
    }
}

#[tauri::command]
pub async fn refresh_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let before = state.selected();
    let result = refresh_one(&state, &id, Refresh::Now).await;
    rebuild(&state)?;
    guard_selected(&app, before, Gone::ByProvider).await;
    notify(&app);
    Ok(result?)
}

/// Открывает в браузере поддержку (`support`) или сайт (`site`) провайдера подписки.
/// Адрес берётся из заголовков подписки (только https), окно его не передаёт.
#[tauri::command]
pub fn open_subscription_link(
    id: String,
    which: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let url = {
        let guard = state.store.lock().map_err(lock_err)?;
        let sub = guard
            .as_ref()
            .and_then(|s| s.get(&id))
            .ok_or(SubsError::Gone)?;
        match which.as_str() {
            "support" => sub.meta.support_url.clone(),
            "site" => sub.meta.web_page_url.clone(),
            _ => None,
        }
        .ok_or(kvt_core::i18n::tr(
            "Провайдер не указал такой ссылки.",
            "The provider didn't specify such a link.",
        ))?
    };
    Ok(crate::about::shell_open(&url)?)
}

/// «Обновить все» во вкладке «Подписки». Возвращает, сколько не обновилось: причины
/// видны у каждой подписки.
#[tauri::command]
pub async fn refresh_all_subscriptions(app: AppHandle) -> Result<usize, String> {
    Ok(refresh_all(&app).await?)
}

/// Обновляет все подписки по ссылке (пункт трея). Возвращает, сколько не обновилось.
pub(crate) async fn refresh_all(app: &AppHandle) -> Result<usize, SubsError> {
    let state = app.state::<AppState>();
    let ids: Vec<String> = {
        let guard = state.store.lock().map_err(lock_err)?;
        guard
            .as_ref()
            .map(|s| {
                s.subscriptions
                    .iter()
                    .filter(|s| s.url.is_some())
                    .map(|s| s.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = state.selected();
    let mut failed = 0;
    for id in &ids {
        if let Err(e) = refresh_one(&state, id, Refresh::Batch).await {
            tracing::warn!(error = %e, "подписка не обновилась");
            failed += 1;
        }
    }
    rebuild(&state)?;
    guard_selected(app, before, Gone::ByProvider).await;
    notify(app);
    Ok(failed)
}

/// Фоновое обновление по расписанию провайдера (`profile-update-interval`,
/// не чаще раза в час, с разбросом). Первая проверка — через минуту после запуска.
pub fn spawn_updater(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let due = app
                .state::<AppState>()
                .store
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.due(now())))
                .unwrap_or_default();
            if !due.is_empty() {
                let state = app.state::<AppState>();
                let before = state.selected();
                for (id, _) in &due {
                    if let Err(e) = refresh_one(&state, id, Refresh::Scheduled).await {
                        tracing::warn!(error = %e, "подписка не обновилась");
                    }
                }
                let _ = rebuild(&state);
                guard_selected(&app, before, Gone::ByProvider).await;
                notify(&app);
            }
            tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        }
    });
}
