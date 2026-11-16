//! Тексты трея: статус и сеанс для первой строки, подсказка значка, короткие
//! названия режима и стратегии, обрезка длинных имён.

use super::*;

/// `general` → «Основная», `general (ALT4)` → «ALT4» (как `strategyTitle` в окне).
pub(super) fn strategy_title(id: &str) -> String {
    match id
        .strip_prefix("general (")
        .and_then(|s| s.strip_suffix(')'))
    {
        Some(inner) => inner.to_owned(),
        None if id == "general" => tr("Основная", "Main").into(),
        None => id.to_owned(),
    }
}

pub(super) fn mode_title(mode: &str) -> &'static str {
    match mode {
        "hybrid" => tr("Гибрид", "Hybrid"),
        "zapret" => "Zapret",
        _ => "VPN",
    }
}

/// 42 с → «меньше минуты», 4320 с → «1 ч 12 мин».
pub(crate) fn elapsed_text(secs: u64) -> String {
    let (h, m) = (secs / 3600, secs % 3600 / 60);
    match (h, m) {
        (0, 0) => tr("меньше минуты", "under a minute").into(),
        (0, m) => trf!("{m} мин", "{m} min"),
        (h, 0) => trf!("{h} ч", "{h} h"),
        (h, m) => trf!("{h} ч {m} мин", "{h} h {m} min"),
    }
}

/// 84 МБ, 1,2 ГБ — коротко, для меню и подсказки.
pub(crate) fn bytes_text(bytes: u64) -> String {
    const RU: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    const EN: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let en = kvt_core::i18n::is_en();
    let units = if en { EN } else { RU };
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let text = if unit == 0 || value >= 10.0 {
        format!("{value:.0}")
    } else {
        let text = format!("{value:.1}");
        if en {
            text
        } else {
            text.replace('.', ",")
        }
    };
    format!("{text} {}", units[unit])
}

/// Укорачивает название и экранирует `&` (в меню Windows это мнемоника).
pub(super) fn menu_text(text: &str) -> String {
    shorten(text, NAME_LEN)
}

/// Значение в названии подменю — короче пункта, чтобы меню не раздувалось вширь.
pub(super) fn menu_text_short(text: &str) -> String {
    shorten(text, 24)
}

pub(super) fn shorten(text: &str, len: usize) -> String {
    let short: String = if text.chars().count() > len {
        let mut s: String = text.chars().take(len - 1).collect();
        s.push('…');
        s
    } else {
        text.to_owned()
    };
    short.replace('&', "&&")
}

pub(super) fn describe(
    state: &AppState,
    status: Option<&ServiceStatus>,
    session: Option<Session>,
    tunnel: Option<bool>,
) -> (View, Tone) {
    let (mode, ks) = state
        .choice
        .lock()
        .map(|c| {
            (
                c.mode.clone().unwrap_or_else(|| "vpn".into()),
                c.kill_switch,
            )
        })
        .unwrap_or_else(|_| ("vpn".into(), false));
    let server = state.selected().map(|e| display_name(&e.server));
    let server_text = server.unwrap_or_else(|| tr("сервер не выбран", "no server selected").into());
    // «VPN · 1 ч 12 мин · ↓ 84 МБ»: что работает и сколько.
    let with_session = |head: String| {
        let mut t = head;
        if let Some(s) = session {
            t.push_str(" · ");
            t.push_str(&elapsed_text(s.secs));
            if let Some(rx) = s.rx {
                t.push_str(&format!(" · ↓ {}", bytes_text(rx)));
            }
        }
        t
    };
    // Вид, заголовок, подробности, вторая строка подсказки, значок.
    let (kind, title, detail, hint, tone) = match status {
        Some(ServiceStatus::Connected { .. }) if tunnel == Some(false) => (
            "connected",
            tr("Сайты не открываются", "Sites don't open").to_owned(),
            trf!(
                "{server_text} не пропускает данные",
                "{server_text} passes no data"
            ),
            trf!(
                "{server_text} не пропускает данные",
                "{server_text} passes no data"
            ),
            Tone::Warn,
        ),
        Some(ServiceStatus::Connected { .. }) => (
            "connected",
            trf!("Подключено — {server_text}", "Connected — {server_text}"),
            with_session(mode_title(&mode).to_owned()),
            format!("{} · {server_text}", mode_title(&mode)),
            Tone::Vpn,
        ),
        Some(ServiceStatus::Zapret { strategy }) => {
            let strategy = trf!("стратегия {}", "strategy {}", strategy_title(strategy));
            (
                "zapret",
                tr("Zapret работает", "Zapret is on").to_owned(),
                with_session(trf!("Без VPN · {strategy}", "No VPN · {strategy}")),
                trf!("Без VPN · {strategy}", "No VPN · {strategy}"),
                Tone::Zapret,
            )
        }
        Some(ServiceStatus::Connecting) => {
            let detail = if mode == "zapret" {
                tr("Zapret · без VPN", "Zapret · no VPN").to_owned()
            } else {
                format!("{} · {server_text}", mode_title(&mode))
            };
            (
                "connecting",
                tr("Подключение…", "Connecting…").to_owned(),
                detail.clone(),
                detail,
                Tone::Connecting,
            )
        }
        Some(ServiceStatus::Failed { reason, blocked }) => {
            if *blocked || (ks && reason.to_lowercase().contains("kill switch")) {
                let detail = tr(
                    "VPN остановился, kill switch не выпускает трафик",
                    "VPN stopped, the kill switch is blocking traffic",
                )
                .to_owned();
                (
                    "failed",
                    tr("Интернет закрыт", "Internet blocked").to_owned(),
                    detail.clone(),
                    detail,
                    Tone::Error,
                )
            } else {
                let short: String = reason.chars().take(60).collect();
                let detail = if short.len() < reason.len() {
                    format!("{short}…")
                } else {
                    short
                };
                (
                    "failed",
                    tr("Ошибка подключения", "Connection error").to_owned(),
                    detail.clone(),
                    detail,
                    Tone::Error,
                )
            }
        }
        Some(ServiceStatus::Disconnected) => {
            let detail = if mode == "zapret" {
                tr("Zapret · без VPN", "Zapret · no VPN").to_owned()
            } else {
                format!("{} · {server_text}", mode_title(&mode))
            };
            (
                "disconnected",
                tr("Отключено", "Disconnected").to_owned(),
                detail.clone(),
                detail,
                Tone::Off,
            )
        }
        None if crate::service_client::version_mismatch() => (
            "mismatch",
            tr(
                "Окно и служба KVT разных версий",
                "KVT window and service versions differ",
            )
            .to_owned(),
            tr(
                "Установите KVT заново — настройки сохранятся",
                "Reinstall KVT — your settings will be kept",
            )
            .to_owned(),
            tr("Установите KVT заново", "Reinstall KVT").to_owned(),
            Tone::Error,
        ),
        None => (
            "no_service",
            tr("Служба KVT не запущена", "KVT service isn't running").to_owned(),
            tr("Откройте KVT, чтобы запустить её", "Open KVT to start it").to_owned(),
            tr("Откройте KVT, чтобы запустить её", "Open KVT to start it").to_owned(),
            Tone::Error,
        ),
    };
    // Подсказка Windows — до 127 символов: «KVT — статус» и подробность.
    let tooltip: String = format!(
        "KVT — {}
{hint}",
        tooltip_title(kind, tone, &title)
    )
    .chars()
    .take(127)
    .collect();
    let view = View {
        kind,
        title: menu_text_long(&title),
        detail: menu_text_long(&detail),
        tooltip,
    };
    (view, tone)
}

/// Статус для подсказки: без названия сервера, оно во второй строке.
pub(super) fn tooltip_title(kind: &str, tone: Tone, title: &str) -> String {
    match kind {
        "connected" if tone == Tone::Vpn => tr("подключено", "connected").to_owned(),
        "no_service" => tr("служба не запущена", "service isn't running").to_owned(),
        "mismatch" => tr(
            "окно и служба разных версий",
            "window and service versions differ",
        )
        .to_owned(),
        _ => {
            let mut chars = title.chars();
            chars
                .next()
                .map(|c| c.to_lowercase().chain(chars).collect())
                .unwrap_or_default()
        }
    }
}

/// Заголовок длиннее названия сервера, но тоже без `&`-мнемоник.
pub(super) fn menu_text_long(text: &str) -> String {
    text.replace('&', "&&")
}
