//! Утечки мимо VPN: системный прокси, прокси WinHTTP, Teredo, DNS адаптеров и браузеров.

use super::foreign::is_tunnel_adapter;
use super::{winhttp_proxy, Facts, Finding, Fix, Group, Level, ServiceFix};
use crate::i18n::tr;
use crate::trf;

pub(super) fn leaks(facts: &Facts, out: &mut Vec<Finding>) {
    use Group::Leaks;
    let p = &facts.proxy;
    let pac = p.auto_config_url.trim();
    if p.enable != 0 || !pac.is_empty() {
        let target = if p.enable != 0 && !p.server.trim().is_empty() {
            p.server.trim().to_owned()
        } else {
            trf!("сценарий {pac}", "script {pac}")
        };
        out.push(
            Finding::new(
                Leaks,
                Level::Warning,
                tr("Включён системный прокси", "System proxy is on"),
                trf!(
                    "Браузеры и другие программы отправляют трафик на {target} — обычно это остаток \
                     другого VPN-клиента. Если та программа закрыта, сайты не открываются; если \
                     запущена — трафик идёт через неё, а не через KVT.",
                    "Browsers and other apps send traffic to {target} — usually a leftover from \
                     another VPN client. If that app is closed, sites won't open; if it's running, \
                     traffic goes through it instead of KVT."
                ),
            )
            .fix(Fix::DisableSystemProxy),
        );
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            tr("Системный прокси", "System proxy"),
            tr(
                "Не задан: программы выходят в сеть обычным путём, через туннель KVT.",
                "Not set: apps reach the internet the normal way, through the KVT tunnel.",
            ),
        ));
    }

    match winhttp_proxy(&facts.winhttp) {
        Some(proxy) => out.push(
            Finding::new(
                Leaks,
                Level::Warning,
                tr("Прокси WinHTTP", "WinHTTP proxy"),
                trf!(
                    "Службы Windows (обновления, Microsoft Store) ходят в сеть через {proxy}. \
                     Обычно это остаток другого VPN-клиента.",
                    "Windows services (updates, Microsoft Store) go online through {proxy}. \
                     This is usually a leftover from another VPN client."
                ),
            )
            .fix(Fix::Service(ServiceFix::ResetWinHttpProxy)),
        ),
        None => out.push(Finding::new(
            Leaks,
            Level::Ok,
            tr("Прокси WinHTTP", "WinHTTP proxy"),
            tr("Не задан.", "Not set."),
        )),
    }

    let teredo_state = facts.teredo.state.to_lowercase();
    let teredo_off = facts.teredo.kind.eq_ignore_ascii_case("disabled");
    if !teredo_off && matches!(teredo_state.as_str(), "qualified" | "dormant" | "probe") {
        out.push(
            Finding::new(
                Leaks,
                Level::Warning,
                tr("Включён Teredo", "Teredo is on"),
                tr(
                    "Teredo даёт компьютеру адрес IPv6 через туннель поверх IPv4. Через него сайты \
                     могут увидеть настоящий адрес мимо VPN. Он нужен только старым играм и Xbox Live.",
                    "Teredo gives the computer an IPv6 address through a tunnel over IPv4. Sites can \
                     see your real address through it, bypassing the VPN. Only old games and Xbox Live need it.",
                ),
            )
            .fix(Fix::Service(ServiceFix::DisableTeredo)),
        );
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            "Teredo",
            tr("Выключен или не используется.", "Off or not in use."),
        ));
    }

    let manual: Vec<String> = facts
        .adapters
        .iter()
        .filter(|a| a.status.eq_ignore_ascii_case("up") && !a.static_dns.trim().is_empty())
        .filter(|a| !is_tunnel_adapter(a))
        .map(|a| {
            let servers = a
                .static_dns
                .split([',', ' '])
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} — {servers}", a.name)
        })
        .collect();
    if manual.is_empty() {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            tr("DNS сетевых адаптеров", "Network adapter DNS"),
            tr(
                "Получается автоматически от роутера.",
                "Obtained automatically from the router.",
            ),
        ));
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Info,
            tr("DNS прописан вручную", "DNS is set manually"),
            trf!(
                "{}. При подключённом VPN это не мешает: KVT шифрует DNS и отправляет его в \
                 туннель. Без VPN эти серверы видят, какие сайты вы открываете.",
                "{}. This is fine while the VPN is on: KVT encrypts DNS and sends it through the \
                 tunnel. Without the VPN, these servers see which sites you open.",
                manual.join("; ")
            ),
        ));
    }

    let own_doh: Vec<String> = facts
        .browsers
        .iter()
        .filter_map(|b| {
            let enabled = match b.browser.as_str() {
                "firefox" => matches!(b.mode.trim(), "2" | "3"),
                _ => b.mode.eq_ignore_ascii_case("secure"),
            };
            enabled.then(|| {
                let resolver = doh_host(&b.templates);
                match resolver {
                    Some(r) => format!("{} ({r})", browser_title(&b.browser)),
                    None => browser_title(&b.browser).to_owned(),
                }
            })
        })
        .collect();
    if own_doh.is_empty() {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            tr("DNS в браузерах", "DNS in browsers"),
            tr(
                "Браузеры используют DNS системы — его настраивает KVT.",
                "Browsers use the system DNS, which KVT configures.",
            ),
        ));
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Info,
            tr("Браузер использует свой DNS", "A browser uses its own DNS"),
            trf!(
                "{}: защищённый DNS включён в настройках браузера. Запросы зашифрованы, но \
                 идут мимо DNS KVT — если сайты из списков маршрутизации открываются не так, \
                 выключите «Безопасный DNS» в настройках браузера.",
                "{}: secure DNS is on in the browser settings. Queries are encrypted but bypass \
                 KVT's DNS — if sites from the routing lists open the wrong way, turn off \
                 “Secure DNS” in the browser settings.",
                own_doh.join(", ")
            ),
        ));
    }
}

fn browser_title(id: &str) -> &str {
    match id {
        "chrome" => "Google Chrome",
        "edge" => "Microsoft Edge",
        "yandex" => tr("Яндекс Браузер", "Yandex Browser"),
        "brave" => "Brave",
        "firefox" => "Firefox",
        other => other,
    }
}

/// Хост первого DoH-шаблона (`https://dns.google/dns-query{?dns}` → `dns.google`).
fn doh_host(templates: &str) -> Option<String> {
    let first = templates.split_whitespace().next()?;
    let host = crate::netlog::host_of(first);
    (!host.is_empty()).then_some(host)
}
