//! Программы, которые мешают VPN: другие VPN-клиенты, чужие туннели, антивирусы с проверкой HTTPS.

use super::foreign::{is_own, is_own_adapter, is_tunnel_adapter, CORES, VPN_CLIENTS};
use super::{Adapter, Facts, Finding, Fix, Group, Level, OwnDirs};
use crate::i18n::tr;
use crate::trf;

/// Антивирусы, которые по умолчанию проверяют HTTPS-соединения.
const HTTPS_SCANNERS: &[&str] = &[
    "kaspersky",
    "eset",
    "avast",
    "avg",
    "bitdefender",
    "dr.web",
    "norton",
    "mcafee",
];

pub(super) fn conflicts(facts: &Facts, own: &OwnDirs, out: &mut Vec<Finding>) {
    use Group::Conflicts;
    let mut seen = Vec::new();
    let mut clients = Vec::new();
    for p in &facts.processes {
        let name = p.name.to_lowercase();
        let title = VPN_CLIENTS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, t)| *t)
            .or_else(|| {
                let foreign_core =
                    CORES.contains(&name.as_str()) && !p.path.is_empty() && !is_own(&p.path, own);
                foreign_core.then_some(p.name.as_str())
            });
        if let Some(title) = title {
            if is_own(&p.path, own) || seen.contains(&title) {
                continue;
            }
            seen.push(title);
            clients.push((title.to_owned(), p.pid));
        }
    }
    if clients.is_empty() {
        out.push(Finding::new(
            Conflicts,
            Level::Ok,
            tr("Другие VPN-клиенты", "Other VPN clients"),
            tr("Не запущены.", "Not running."),
        ));
    }
    for (title, pid) in clients {
        out.push(
            Finding::new(
                Conflicts,
                Level::Warning,
                trf!("Запущен {title}", "{title} is running"),
                tr(
                    "Два VPN одновременно спорят за маршруты и DNS: часть трафика уходит не туда, \
                     подключение обрывается. Закройте другой клиент, пока работает KVT.",
                    "Two VPNs at once fight over routes and DNS: some traffic goes the wrong way and \
                     the connection drops. Close the other client while KVT is running.",
                ),
            )
            .fix(Fix::CloseProcess { pid, name: title }),
        );
    }

    let adapters: Vec<&Adapter> = facts
        .adapters
        .iter()
        .filter(|a| {
            a.status.eq_ignore_ascii_case("up") && is_tunnel_adapter(a) && !is_own_adapter(a)
        })
        .collect();
    if adapters.is_empty() {
        out.push(Finding::new(
            Conflicts,
            Level::Ok,
            tr("Туннели других VPN", "Other VPN tunnels"),
            tr("Активных нет.", "None active."),
        ));
    } else {
        let names: Vec<String> = adapters
            .iter()
            .map(|a| format!("{} ({})", a.name, a.description))
            .collect();
        out.push(Finding::new(
            Conflicts,
            Level::Warning,
            tr("Активен туннель другого VPN", "Another VPN's tunnel is active"),
            trf!(
                "{}. Пока он подключён, трафик может идти через него. Отключите VPN в той программе.",
                "{}. While it's connected, traffic may go through it. Disconnect the VPN in that app.",
                names.join(", ")
            ),
        ));
    }

    let scanners: Vec<&String> = facts
        .antivirus
        .iter()
        .filter(|name| {
            let n = name.to_lowercase();
            HTTPS_SCANNERS.iter().any(|s| n.contains(s))
        })
        .collect();
    if scanners.is_empty() {
        out.push(Finding::new(
            Conflicts,
            Level::Ok,
            tr("Антивирус", "Antivirus"),
            tr(
                "Антивирусов, которые перехватывают HTTPS, не найдено.",
                "No antivirus that intercepts HTTPS was found.",
            ),
        ));
    } else {
        let names: Vec<&str> = scanners.iter().map(|s| s.as_str()).collect();
        out.push(Finding::new(
            Conflicts,
            Level::Info,
            tr("Антивирус проверяет HTTPS", "Antivirus scans HTTPS"),
            trf!(
                "{} может перехватывать защищённые соединения. Если подписки не загружаются или \
                 проверка серверов ошибается, добавьте папку KVT в исключения или выключите \
                 «Проверку защищённых соединений».",
                "{} may intercept secure connections. If subscriptions don't load or server \
                 checks go wrong, add the KVT folder to exclusions or turn off encrypted \
                 connection scanning.",
                names.join(", ")
            ),
        ));
    }
}
