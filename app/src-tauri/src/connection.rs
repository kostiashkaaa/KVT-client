//! Подключение: план для службы, подключить и отключить, статус, быстрая
//! проверка серверов, ожидание службы и подключение при старте.

use super::*;

mod error;
pub(crate) use error::ConnectionError;
use service_client::ServiceError;

/// Подключение, которое KVT начал сам (автопереключение, после сна, при запуске),
/// по состоянию на `epoch`. «Отключить», нажатое после проверки `epoch`, но раньше,
/// чем служба приняла «Подключить», служба не отменяет: она прерывает только запуск,
/// начатый до «Отключить». Тогда VPN включился бы вопреки пользователю — отключаем
/// снова. `Err` с текстом отмены — пользователь вмешался.
pub(crate) async fn connect_auto(
    app: &AppHandle,
    epoch: u64,
    verify: bool,
) -> Result<ServiceStatus, ConnectionError> {
    let state = app.state::<AppState>();
    if state.epoch() != epoch {
        return Err(ConnectionError::Cancelled);
    }
    let result = connect_current(app, verify).await;
    if state.disconnected_after(epoch) {
        tracing::info!("пользователь отключился во время автоматического подключения — отключаем");
        let _ = disconnect_service().await;
        tunnel::set(app, None);
        return Err(ConnectionError::Cancelled);
    }
    result
}

/// Серверы одной подписки (`group`) или всех: ключи и серверы.
pub(super) fn servers_of(
    state: &AppState,
    group: Option<&str>,
) -> Result<(Vec<String>, Vec<Server>), ConnectionError> {
    Ok(state
        .servers
        .lock()
        .map_err(|_| ConnectionError::State)?
        .iter()
        .filter(|e| group.is_none_or(|g| e.sub == g))
        .map(|e| (e.key.clone(), e.server.clone()))
        .unzip())
}

/// Быстрая проверка (TCP-пинг без TLS): безопасна для ТСПУ, идёт параллельно.
/// Результат — по ключам серверов.
#[tauri::command]
pub(super) async fn quick_check(
    group: Option<String>,
    state: State<'_, AppState>,
) -> Result<HashMap<String, QuickResult>, String> {
    let (keys, servers) = servers_of(&state, group.as_deref())?;
    let first = state.doh_first();
    let doh = tester::Doh {
        first: &first,
        governor: &state.governor,
    };
    let results = ping_servers(&doh, &servers).await?;
    Ok(keys.into_iter().zip(results).collect())
}

/// TCP-пинг серверов мимо туннеля. С VPN соединение из приложения принял бы сам
/// TUN (за 0 мс, и любой сервер выглядел бы рабочим) — тогда пингует служба,
/// напрямую через физический адаптер. Имена в обоих случаях — через DoH.
pub(crate) async fn ping_servers(
    doh: &tester::Doh<'_>,
    servers: &[Server],
) -> Result<Vec<QuickResult>, ConnectionError> {
    if !matches!(
        query_status().await,
        Ok(Some(
            ServiceStatus::Connected { .. } | ServiceStatus::Connecting
        ))
    ) {
        return Ok(tester::quick_check(servers, doh, Duration::from_secs(3), 8).await);
    }
    let targets = servers
        .iter()
        .map(|s| {
            (!s.protocol.is_quic()).then(|| ipc::PingTarget {
                host: s.address.clone(),
                port: s.port,
            })
        })
        .collect();
    let request = Request::Ping {
        targets,
        doh: doh.first.to_owned(),
    };
    match service_client::call(request).await {
        Ok(Response::Ping { results }) if results.len() == servers.len() => Ok(results),
        Ok(Response::Error { message }) => Err(ConnectionError::remote(message)),
        Ok(_) => Err(ConnectionError::Unexpected),
        Err(e) => Err(e.into()),
    }
}

/// Строит план подключения по текущему выбору и отправляет его службе.
/// Конфиг ядра собирает служба. `verify` — после подключения проверить в фоне,
/// что через туннель идут данные (автопереключение проверяет само).
pub(super) async fn connect_current(
    app: &AppHandle,
    verify: bool,
) -> Result<ServiceStatus, ConnectionError> {
    let state = app.state::<AppState>();
    tunnel::set(app, None);
    let status = send_plan(&state).await?;
    if verify && matches!(status, ServiceStatus::Connected { .. }) {
        tunnel::spawn_verify(app.clone());
    }
    // Итог сервисов после подключения уже сброшен. Проверку запускает `spawn_verify`
    // (подключение с проверкой туннеля); здесь — остальные: режим «Zapret» без туннеля и
    // автопереключение, которое проверяет туннель само. У winws есть несколько секунд,
    // чтобы встать.
    let tunnel_checked = verify && matches!(status, ServiceStatus::Connected { .. });
    if !tunnel_checked
        && matches!(
            status,
            ServiceStatus::Zapret { .. } | ServiceStatus::Connected { .. }
        )
    {
        services::spawn_after_connect(app.clone(), std::time::Duration::from_secs(3));
    }
    Ok(status)
}

/// Что отправить службе для текущего выбора.
pub(crate) enum Plan {
    Vpn(Box<ConnectPlan>),
    /// Только zapret: сервер не нужен, winws работает на всех интерфейсах.
    Zapret(kvt_core::ipc::ZapretPlan),
}

/// Подключение к выбранному серверу (или только zapret).
pub(super) async fn send_plan(state: &AppState) -> Result<ServiceStatus, ConnectionError> {
    let mut with = None;
    let request = match build_plan(state)? {
        Plan::Vpn(plan) => {
            with = Some((plan.routing.clone(), plan.zapret.is_some()));
            Request::Connect(plan)
        }
        Plan::Zapret(plan) => Request::StartZapret(Box::new(plan)),
    };
    match service_client::call(request).await? {
        Response::Status { status, session } => {
            if let Ok(mut s) = state.session.lock() {
                *s = session;
            }
            // Плитки сервисов считают путь по плану, с которым подключились.
            state.services.connected_with(&status, with);
            Ok(status)
        }
        Response::Error { message } => Err(ConnectionError::remote(message)),
        _ => Err(ConnectionError::Unexpected),
    }
}

/// План по текущему выбору. Конфиг ядра из него собирает служба (а для
/// экспорта диагностики — приложение тем же компилятором).
pub(crate) fn build_plan(state: &AppState) -> Result<Plan, ConnectionError> {
    let choice = state
        .choice
        .lock()
        .map_err(|_| ConnectionError::State)?
        .clone();
    let mode = choice.mode.unwrap_or_else(|| "vpn".into());
    let network = zapret::network_key(state);
    if mode == "zapret" {
        return Ok(Plan::Zapret(choice.zapret.plan(network.as_deref())));
    }
    let server = state.selected().ok_or(ConnectionError::NoServer)?.server;

    let mut routing = presets::from_settings(&choice.routing)
        .with_servers(server.endpoints())
        .with_health_check()
        .with_update_hosts();
    if mode == "hybrid" {
        routing.extend(presets::zapret_youtube_discord());
    }
    // Прокси Telegram: путь его соединений, пока работает VPN.
    if choice.zapret.telegram {
        routing.extend(tgproxy::route_rules(
            mode == "hybrid",
            choice.zapret.telegram_route,
        ));
    }
    routing.validate().map_err(|e| {
        tracing::warn!(error = %e, "маршрутизация противоречива");
        ConnectionError::Routing
    })?;
    let sni = server
        .visible_sni()
        .map(str::to_ascii_lowercase)
        .filter(|d| kvt_core::zapret::valid_domain(d) && d.parse::<std::net::IpAddr>().is_err());
    let plan = ConnectPlan {
        core: select_core(&server).core,
        server,
        routing,
        kill_switch: choice.kill_switch,
        dns: DnsPlan::from_ids(&choice.dns.local, &choice.dns.remote).map_err(|e| {
            tracing::warn!(error = %e, "DNS из настроек не поддерживается");
            ConnectionError::Dns
        })?,
        // Гибрид: winws рядом с ядром, домены zapret служба берёт из RoutingPlan.
        // SNI сервера winws не трогает: адрес сервера служба исключает сама, но если он
        // задан именем и разрешился иначе, чем у ядра, рукопожатие VPN всё равно попало
        // бы под стратегию, когда SNI совпадает с доменом из списков zapret.
        zapret: (mode == "hybrid").then(|| {
            let mut z = choice.zapret.plan(network.as_deref());
            if let Some(sni) = sni.clone() {
                if !z.exclude_domains.contains(&sni) {
                    z.exclude_domains.push(sni);
                }
            }
            z
        }),
    };
    Ok(Plan::Vpn(Box::new(plan)))
}

#[tauri::command]
pub(super) async fn connect(app: AppHandle) -> Result<ServiceStatus, String> {
    app.state::<AppState>().user_acted();
    let result = connect_current(&app, true).await;
    tray::refresh(&app).await;
    Ok(result?)
}

/// Сообщения, которые появились до открытия окна (окно забирает их один раз).
#[tauri::command]
pub(super) fn take_notices(state: State<'_, AppState>) -> Vec<String> {
    state
        .notices
        .lock()
        .map(|mut n| std::mem::take(&mut *n))
        .unwrap_or_default()
}

/// Проверка утечек: открытые прокси на этом компьютере, маршруты и DNS. Подключён
/// ли VPN, решает служба, а не окно: его статус мог устареть.
#[tauri::command]
pub(super) async fn leak_test(
    state: State<'_, AppState>,
) -> Result<diagnostics::LeakReport, String> {
    let connected = matches!(
        query_status().await,
        Ok(Some(ServiceStatus::Connected { .. }))
    );
    let remote = state
        .choice
        .lock()
        .map_err(crate::errors::state)?
        .dns
        .remote
        .clone();
    Ok(diagnostics::run(connected, &remote).await)
}

pub(super) async fn disconnect_service() -> Result<ServiceStatus, ConnectionError> {
    match service_client::call(Request::Disconnect).await? {
        Response::Ok => Ok(ServiceStatus::Disconnected),
        Response::Error { message } => Err(ConnectionError::remote(message)),
        _ => Err(ConnectionError::Unexpected),
    }
}

#[tauri::command]
pub(super) async fn disconnect(app: AppHandle) -> Result<ServiceStatus, String> {
    app.state::<AppState>().user_disconnected();
    let result = disconnect_service().await;
    tray::refresh(&app).await;
    Ok(result?)
}

/// Статус службы. Если служба не запущена — `None` и текст причины не нужен:
/// интерфейс просто показывает «Отключено».
#[tauri::command]
pub(super) async fn service_status() -> Result<Option<ServiceStatus>, String> {
    Ok(query_status().await?)
}

/// Время и трафик текущего сеанса из последнего ответа службы (без запроса к ней).
#[tauri::command]
pub(super) fn service_session(state: State<'_, AppState>) -> Option<Session> {
    state.session.lock().ok().and_then(|s| *s)
}

pub(super) async fn query_status() -> Result<Option<ServiceStatus>, ConnectionError> {
    let (result, session) = match service_client::call(Request::Status).await {
        Ok(Response::Status { status, session }) => (Ok(Some(status)), session),
        Ok(Response::Error { message }) => (Err(ConnectionError::remote(message)), None),
        Ok(_) => (Err(ConnectionError::Unexpected), None),
        Err(_) => (Ok(None), None),
    };
    if let Some(app) = APP.get() {
        if let Ok(mut s) = app.state::<AppState>().session.lock() {
            *s = session;
        }
    }
    result
}

/// Сколько ждать службу после запуска KVT. Служба стоит в отложенном автозапуске:
/// Windows запускает её примерно через 2 минуты после загрузки, а KVT из автозагрузки
/// стартует раньше. Поэтому KVT запускает службу сам (это разрешено пользователю),
/// а если не вышло — ждёт с запасом.
pub(super) const SERVICE_WAIT: Duration = Duration::from_secs(5 * 60);

/// Ждёт, пока служба начнёт отвечать. Если её нет — один раз просит Windows её
/// запустить. `Err` — служба так и не ответила (текст для пользователя).
pub(crate) async fn wait_for_service() -> Result<ServiceStatus, ConnectionError> {
    let start = Instant::now();
    let mut asked = false;
    loop {
        if let Ok(Some(status)) = query_status().await {
            return Ok(status);
        }
        if service_client::version_mismatch() {
            return Err(ServiceError::VersionMismatch.into());
        }
        if !asked {
            asked = true;
            match tauri::async_runtime::spawn_blocking(about::start_blocking).await {
                Ok(Ok(())) => tracing::info!("служба KVT запущена из приложения"),
                // Не установлена или отключена — ждать бесполезно.
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {}
            }
        }
        if start.elapsed() >= SERVICE_WAIT {
            return Err(ServiceError::NotRunning.into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Запуск KVT: служба должна работать сразу, а не через две минуты отложенного
/// автозапуска — иначе трей и окно показывают «Служба не запущена».
/// С «Подключаться при запуске» — ещё и подключается, если ничего не работает.
pub(super) fn spawn_connect_on_start(app: AppHandle) {
    let enabled = app
        .state::<AppState>()
        .choice
        .lock()
        .map(|c| c.connect_on_start)
        .unwrap_or(false);
    if !enabled {
        tauri::async_runtime::spawn(async move {
            if matches!(query_status().await, Ok(Some(_))) || service_client::version_mismatch() {
                return;
            }
            match tauri::async_runtime::spawn_blocking(about::start_blocking).await {
                Ok(Ok(())) => tracing::info!("служба KVT запущена из приложения"),
                // Окно покажет кнопку «Запустить службу» с понятной причиной.
                Ok(Err(message)) => tracing::warn!(%message, "служба KVT не запустилась"),
                Err(_) => {}
            }
            tray::invalidate(&app);
        });
        return;
    }
    tauri::async_runtime::spawn(async move {
        let epoch = app.state::<AppState>().epoch();
        let result = match wait_for_service().await {
            // Пока ждали, пользователь сам подключился или отключился.
            Ok(_) if app.state::<AppState>().epoch() != epoch => return,
            Ok(ServiceStatus::Disconnected | ServiceStatus::Failed { .. }) => {
                match connect_auto(&app, epoch, true).await {
                    Err(ConnectionError::Cancelled) => return,
                    other => other.map(|_| ()),
                }
            }
            // Уже подключено (профиль сети) или идёт подключение.
            Ok(_) => return,
            Err(message) => Err(message),
        };
        if let Err(message) = result {
            notify::error(
                &app,
                &kvt_core::trf!(
                    "Не удалось подключиться при запуске: {message}",
                    "Couldn't connect on startup: {message}"
                ),
            );
        }
        tray::invalidate(&app);
    });
}
