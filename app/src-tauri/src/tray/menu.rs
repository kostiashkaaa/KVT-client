//! Меню трея: сервер, режим, маршрутизация, стратегия zapret, переключатели и
//! инструменты. Строится заново по событиям (`invalidate`).

use super::*;

/// Порядок серверов подписки в меню: рабочие по задержке, затем не проверенные,
/// затем неработающие. Выбранный всегда попадает в меню.
pub(super) fn menu_servers<'a>(
    servers: &'a [crate::ServerSummary],
    outcomes: &HashMap<String, Outcome>,
    selected: Option<&str>,
) -> Vec<(&'a crate::ServerSummary, Option<String>)> {
    use kvt_core::probe::Verdict;
    let mut ranked: Vec<(u8, u64, usize, Option<String>)> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| match outcomes.get(&s.key) {
            Some(Outcome::Checked {
                verdict: Verdict::Works | Verdict::Slow,
                latency_ms,
            }) => (
                0,
                latency_ms.unwrap_or(u64::MAX),
                i,
                latency_ms.map(|ms| trf!("{ms} мс", "{ms} ms")),
            ),
            Some(Outcome::Checked { .. }) => {
                (2, 0, i, Some(tr("не работает", "not working").into()))
            }
            _ => (1, 0, i, None),
        })
        .collect();
    ranked.sort_by_key(|&(class, latency, i, _)| (class, latency, i));
    let mut picked: Vec<(usize, Option<String>)> = ranked
        .iter()
        .take(SERVERS_IN_MENU)
        .map(|(_, _, i, note)| (*i, note.clone()))
        .collect();
    if let Some(sel) = selected {
        if let Some((_, _, i, note)) = ranked.iter().find(|(_, _, i, _)| servers[*i].key == sel) {
            if !picked.iter().any(|(p, _)| p == i) {
                picked.push((*i, note.clone()));
            }
        }
    }
    picked.into_iter().map(|(i, n)| (&servers[i], n)).collect()
}

pub(super) fn server_label(name: &str, note: Option<&str>) -> String {
    match note {
        Some(n) => format!("{} · {n}", menu_text(name)),
        None => menu_text(name),
    }
}

pub(super) fn build_menu(
    app: &AppHandle,
    tray: &Tray,
    view: &View,
    tone: Tone,
) -> tauri::Result<Menu<Wry>> {
    let state = app.state::<AppState>();
    let choice = state.choice.lock().map(|c| c.clone()).unwrap_or_default();
    let mode = choice.mode.clone().unwrap_or_else(|| "vpn".into());
    let selected = choice.server.clone();
    let status = tray.status.lock().ok().and_then(|s| s.clone());
    let active = matches!(
        status,
        Some(ServiceStatus::Connected { .. } | ServiceStatus::Zapret { .. })
    );
    let connecting = matches!(status, Some(ServiceStatus::Connecting));
    // Ядро остановилось, а kill switch держит интернет закрытым.
    let blocked = matches!(status, Some(ServiceStatus::Failed { blocked: true, .. }));
    let service = status.is_some();

    let menu = Menu::new(app)?;
    let sep = || PredefinedMenuItem::separator(app);

    // Заголовок: значок и статус (клик открывает окно), под ним — сеанс.
    let title = IconMenuItem::with_id(
        app,
        "status",
        &view.title,
        true,
        Some(icon::render(tone, 0, icon_size(app))),
        None::<&str>,
    )?;
    let detail = MenuItem::with_id(app, "detail", &view.detail, false, None::<&str>)?;
    menu.append(&title)?;
    menu.append(&detail)?;
    if let Ok(mut h) = tray.header.lock() {
        *h = Some((title, detail));
    }
    menu.append(&sep()?)?;

    // Подключение.
    let can_connect = service && (mode == "zapret" || state.selected().is_some());
    let zapret_only =
        matches!(status, Some(ServiceStatus::Zapret { .. })) || (!active && mode == "zapret");
    let toggle = if active {
        let label = if zapret_only {
            tr("Выключить zapret", "Turn off zapret")
        } else {
            tr("Отключить", "Disconnect")
        };
        MenuItem::with_id(app, "toggle", label, true, None::<&str>)?
    } else if blocked {
        MenuItem::with_id(
            app,
            "toggle",
            tr(
                "Отключить и вернуть интернет",
                "Disconnect and restore internet",
            ),
            true,
            None::<&str>,
        )?
    } else if connecting {
        // Служба прерывает долгий запуск по «Отключить».
        MenuItem::with_id(
            app,
            "toggle",
            tr("Отменить подключение", "Cancel connection"),
            true,
            None::<&str>,
        )?
    } else {
        let label = if zapret_only {
            tr("Включить zapret", "Turn on zapret")
        } else if service && !can_connect {
            tr("Подключить — выберите сервер", "Connect — pick a server")
        } else {
            tr("Подключить", "Connect")
        };
        MenuItem::with_id(app, "toggle", label, can_connect, None::<&str>)?
    };
    menu.append(&toggle)?;
    if active {
        menu.append(&MenuItem::with_id(
            app,
            "reconnect",
            tr("Переподключить", "Reconnect"),
            true,
            None::<&str>,
        )?)?;
    }
    menu.append(&sep()?)?;

    // Сервер.
    let groups = state.groups.lock().map(|g| g.clone()).unwrap_or_default();
    let outcomes = state.outcomes.lock().map(|o| o.clone()).unwrap_or_default();
    let server_title = match state.selected() {
        Some(e) => trf!(
            "Сервер: {}",
            "Server: {}",
            menu_text_short(&display_name(&e.server))
        ),
        None => tr("Сервер", "Server").to_owned(),
    };
    let servers_menu = Submenu::with_id(app, "servers", server_title, true)?;
    let names: HashMap<&str, &crate::ServerSummary> = groups
        .iter()
        .flat_map(|g| g.servers.iter().map(|s| (s.key.as_str(), s)))
        .collect();
    let recent: Vec<&crate::ServerSummary> = choice
        .recent
        .iter()
        .filter_map(|k| names.get(k.as_str()).copied())
        .collect();
    if !recent.is_empty() {
        servers_menu.append(&MenuItem::with_id(
            app,
            "recent-title",
            tr("Недавние", "Recent"),
            false,
            None::<&str>,
        )?)?;
        for s in recent {
            servers_menu.append(&CheckMenuItem::with_id(
                app,
                format!("rsrv:{}", s.key),
                menu_text(&s.name),
                true,
                selected.as_deref() == Some(s.key.as_str()),
                None::<&str>,
            )?)?;
        }
        servers_menu.append(&sep()?)?;
    }
    let non_empty: Vec<&crate::catalog::Group> =
        groups.iter().filter(|g| !g.servers.is_empty()).collect();
    let add_servers = |target: &Submenu<Wry>, group: &crate::catalog::Group| -> tauri::Result<()> {
        for (s, note) in menu_servers(&group.servers, &outcomes, selected.as_deref()) {
            target.append(&CheckMenuItem::with_id(
                app,
                format!("srv:{}", s.key),
                server_label(&s.name, note.as_deref()),
                true,
                selected.as_deref() == Some(s.key.as_str()),
                None::<&str>,
            )?)?;
        }
        if group.servers.len() > SERVERS_IN_MENU {
            target.append(&MenuItem::with_id(
                app,
                format!("all:{}", group.id),
                trf!(
                    "Все серверы ({})…",
                    "All servers ({})…",
                    group.servers.len()
                ),
                true,
                None::<&str>,
            )?)?;
        }
        Ok(())
    };
    match non_empty.as_slice() {
        [] => servers_menu.append(&MenuItem::with_id(
            app,
            "add",
            tr("Добавить подписку…", "Add subscription…"),
            true,
            None::<&str>,
        )?)?,
        [only] => add_servers(&servers_menu, only)?,
        many => {
            for group in many {
                let sub = Submenu::new(
                    app,
                    format!("{} ({})", menu_text(&group.title), group.servers.len()),
                    true,
                )?;
                add_servers(&sub, group)?;
                servers_menu.append(&sub)?;
            }
        }
    }
    menu.append(&servers_menu)?;

    // Режим.
    let modes = Submenu::with_id(
        app,
        "modes",
        trf!("Режим: {}", "Mode: {}", mode_title(&mode)),
        true,
    )?;
    for (id, label) in [
        ("vpn", "VPN"),
        (
            "hybrid",
            tr(
                "Гибрид — YouTube и Discord через zapret",
                "Hybrid — YouTube and Discord via zapret",
            ),
        ),
        ("zapret", tr("Zapret — без VPN", "Zapret — no VPN")),
    ] {
        modes.append(&CheckMenuItem::with_id(
            app,
            format!("mode:{id}"),
            label,
            true,
            mode == id,
            None::<&str>,
        )?)?;
    }
    menu.append(&modes)?;

    // Что через VPN — в «Zapret» VPN нет, и пункт не нужен.
    if mode != "zapret" {
        let proxy_all = choice.routing.everything_else == Action::Proxy;
        let route = Submenu::with_id(
            app,
            "route",
            if proxy_all {
                tr(
                    "Через VPN: всё, кроме российского",
                    "Via VPN: everything except Russian sites",
                )
            } else {
                tr(
                    "Через VPN: только заблокированное",
                    "Via VPN: only blocked sites",
                )
            },
            true,
        )?;
        route.append(&CheckMenuItem::with_id(
            app,
            "route:proxy",
            tr("Всё, кроме российского", "Everything except Russian sites"),
            true,
            proxy_all,
            None::<&str>,
        )?)?;
        route.append(&CheckMenuItem::with_id(
            app,
            "route:direct",
            tr("Только заблокированное", "Only blocked sites"),
            true,
            !proxy_all,
            None::<&str>,
        )?)?;
        menu.append(&route)?;
    }

    // Стратегия zapret — только там, где zapret работает.
    if mode != "vpn" {
        let network = crate::zapret::network_key(&state);
        let current = choice.zapret.strategy_for(network.as_deref());
        let mut list = tray
            .strategies
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        if !list.iter().any(|(id, _)| *id == current) {
            list.insert(0, (current.clone(), strategy_title(&current)));
        }
        let strategies = Submenu::with_id(
            app,
            "strategies",
            trf!(
                "Стратегия zapret: {}",
                "zapret strategy: {}",
                menu_text_short(&strategy_title(&current))
            ),
            true,
        )?;
        for (id, title) in list {
            strategies.append(&CheckMenuItem::with_id(
                app,
                format!("strat:{id}"),
                menu_text(&title),
                true,
                id == current,
                None::<&str>,
            )?)?;
        }
        strategies.append(&sep()?)?;
        strategies.append(&MenuItem::with_id(
            app,
            "strat-pick",
            tr("Подобрать заново…", "Pick again…"),
            true,
            None::<&str>,
        )?)?;
        menu.append(&strategies)?;
    }
    menu.append(&sep()?)?;

    menu.append(&CheckMenuItem::with_id(
        app,
        "ks",
        "Kill switch",
        true,
        choice.kill_switch,
        None::<&str>,
    )?)?;
    menu.append(&CheckMenuItem::with_id(
        app,
        "auto",
        tr("Автопереключение сервера", "Auto-switch server"),
        true,
        choice.auto_switch,
        None::<&str>,
    )?)?;
    menu.append(&sep()?)?;

    let tools = Submenu::with_id(app, "tools", tr("Инструменты", "Tools"), true)?;
    let tool_items: [(&str, &str); 3] = [
        (
            "tool:refresh",
            tr("Обновить подписки", "Update subscriptions"),
        ),
        (
            "tool:why",
            tr("Почему не работает?", "Why isn't it working?"),
        ),
        ("tool:journal", tr("Журнал запросов", "Request log")),
    ];
    for (id, label) in tool_items {
        tools.append(&MenuItem::with_id(app, id, label, true, None::<&str>)?)?;
    }
    menu.append(&tools)?;
    menu.append(&sep()?)?;

    let items: [&dyn IsMenuItem<Wry>; 2] = [
        &MenuItem::with_id(
            app,
            "open",
            tr("Открыть KVT", "Open KVT"),
            true,
            None::<&str>,
        )?,
        &MenuItem::with_id(app, "quit", tr("Выход", "Quit"), true, None::<&str>)?,
    ];
    for item in items {
        menu.append(item)?;
    }
    Ok(menu)
}
