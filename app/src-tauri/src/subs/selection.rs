//! Выбранный сервер, когда подписка изменилась: остаться на нём, перейти на
//! его преемника или заменить рабочим.

use super::*;

/// Кто убрал сервер из списка.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Gone {
    /// Пользователь: удалил подписку или ключ, скрыл фильтром.
    ByUser,
    /// Провайдер: обновление подписки.
    ByProvider,
}

/// Выбранный сервер пропал из списка.
///
/// Провайдер часто меняет у сервера адрес или порт (ключ из них) или добавляет к
/// точке второй вариант — тогда выбор переходит на тот же сервер в новой подписке, а
/// если VPN подключён, KVT переподключается к нему. Если провайдер убрал сервер
/// совсем, а автопереключение включено, KVT подключается к рабочей замене, как при
/// сбое. Иначе — и всегда, если сервер убрал сам пользователь, — KVT отключается и
/// говорит об этом, а не переподключается молча к серверу другой подписки.
pub(super) async fn guard_selected(app: &AppHandle, before: Option<catalog::Entry>, gone: Gone) {
    let Some(entry) = before else { return };
    let state = app.state::<AppState>();
    if state.entry(&entry.key).is_some() {
        return;
    }
    // Автопереключение могло как раз перебирать серверы: ждём его и смотрим заново —
    // если выбор уже другой, этот сервер больше не наш.
    let _switching = state.switching.lock().await;
    let still_selected = state
        .choice
        .lock()
        .is_ok_and(|c| c.server.as_deref() == Some(entry.key.as_str()));
    if !still_selected || state.entry(&entry.key).is_some() {
        return;
    }
    let connected = matches!(
        query_status().await,
        Ok(Some(ServiceStatus::Connected { .. }))
    );
    if gone == Gone::ByProvider {
        let next = {
            let entries = state.servers.lock().map(|s| s.clone()).unwrap_or_default();
            catalog::successor(&entries, &entry).cloned()
        };
        if let Some(next) = next {
            follow(app, &entry, &next, connected).await;
            return;
        }
    }
    if !connected {
        return;
    }
    let auto = state.choice.lock().map(|c| c.auto_switch).unwrap_or(false);
    // Замена — такая же смена сервера, как автопереключение: лимит общий.
    if gone == Gone::ByProvider
        && auto
        && watchdog::take_incident(&state)
        && replace(app, &entry).await
    {
        return;
    }
    tracing::info!("выбранный сервер исчез из подписок — VPN отключён");
    state.user_disconnected();
    let _ = disconnect_service().await;
    crate::tray::refresh(app).await;
    let _ = app.emit(
        watchdog::EVENT,
        watchdog::Event::ServerRemoved {
            server: display_name(&entry.server),
        },
    );
}

/// Выбор — на тот же сервер с новым ключом. Подключены, и параметры сменились —
/// переподключаемся (kill switch служба держит); если сменился только ключ, ядро
/// трогать незачем.
pub(super) async fn follow(
    app: &AppHandle,
    old: &catalog::Entry,
    next: &catalog::Entry,
    connected: bool,
) {
    let state = app.state::<AppState>();
    let epoch = state.epoch();
    tracing::info!("у выбранного сервера провайдер сменил адрес, порт или вариант — выбран он же");
    // Пользователь мог за время обновления выбрать другой сервер — его выбор не трогаем.
    let moved = crate::update_choice(app, |c| {
        if c.server.as_deref() == Some(old.key.as_str()) {
            c.server = Some(next.key.clone());
        }
    });
    if !matches!(moved, Ok(c) if c.server.as_deref() == Some(next.key.as_str())) {
        return;
    }
    let _ = app.emit(watchdog::CHOICE_EVENT, ());
    if !connected || old.server == next.server {
        return;
    }
    if let Err(e) = crate::connect_auto(app, epoch, true).await {
        tracing::warn!(error = %e, "переподключение к обновлённому серверу не удалось");
    }
    crate::tray::refresh(app).await;
}

/// Провайдер убрал сервер, через который подключены: подключаемся к рабочей замене,
/// как автопереключение при сбое (сначала из той же подписки). `false` — замены нет
/// или пользователь вмешался; выбор тогда возвращается на прежний ключ.
pub(super) async fn replace(app: &AppHandle, old: &catalog::Entry) -> bool {
    let state = app.state::<AppState>();
    let epoch = state.epoch();
    let from = display_name(&old.server);
    // Последний кандидат, через которого данные не пошли (он записан в выбор).
    let mut failed: Option<String> = None;
    for key in watchdog::alternatives(&state, Some(old)).await {
        if state.epoch() != epoch {
            watchdog::revert_failed(app, failed.as_deref(), Some(&old.key));
            return true;
        }
        if watchdog::switch_to(app, &key, epoch).await.is_ok() {
            if state.epoch() == epoch {
                let to = watchdog::server_name(&state, &key);
                tracing::info!("выбранный сервер исчез из подписки — подключена замена");
                let _ = app.emit(
                    watchdog::EVENT,
                    watchdog::Event::ServerReplaced { from, to },
                );
            }
            return true;
        }
        failed = Some(key);
    }
    if state.epoch() != epoch {
        watchdog::revert_failed(app, failed.as_deref(), Some(&old.key));
        return true;
    }
    let _ = crate::update_choice(app, |c| c.server = Some(old.key.clone()));
    let _ = app.emit(watchdog::CHOICE_EVENT, ());
    false
}
