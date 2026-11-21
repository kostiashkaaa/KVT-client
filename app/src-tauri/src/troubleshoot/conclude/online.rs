//! Сервер, интернет без VPN и туннель: стадия после сети, службы и подписки.

use super::{switch, switch_hint, Out};
use crate::troubleshoot::{Diagnosis, Facts, Fix, StepState, Tone};
use kvt_core::i18n::tr;
use kvt_core::ipc::ServiceStatus;
use kvt_core::tester::QuickResult;
use kvt_core::trf;

/// `Some` — вывод готов (неполадка или подключённый VPN), `None` — идти к проверке
/// сервера. Служба к этому моменту отвечает (`basic` уже ответил бы про неё).
pub(super) fn run(f: &Facts, out: &mut Out) -> Option<Diagnosis> {
    let Some(server) = &f.server else {
        out.step(
            tr("Сервер", "Server"),
            StepState::Fail,
            tr("Сервер не выбран", "No server selected"),
        );
        return Some(out.finish(
            Tone::Warning,
            tr("Не выбран сервер", "No server selected"),
            tr(
                "Выберите сервер в списке на главной.",
                "Pick a server from the list on the home page.",
            ),
            None,
        ));
    };

    // Неполадки службы закрыла `basic`; здесь статуса может не быть только если
    // факты собрали вручную — тогда продолжать не с чем.
    let Some(service) = &f.service else {
        return None;
    };
    let connected = matches!(service, ServiceStatus::Connected { .. });
    if !connected && f.internet == Some(false) {
        out.step(
            tr("Интернет без VPN", "Internet without VPN"),
            StepState::Fail,
            tr(
                "Сайты недоступны и без VPN",
                "Sites are unreachable even without the VPN",
            ),
        );
        return Some(out.finish(
            Tone::Error,
            tr("Интернет не работает даже без VPN", "The internet doesn't work even without the VPN"),
            tr(
                "Сеть есть, но в интернет выйти не получается. Проблема у провайдера или роутера — \
                 KVT здесь не поможет.",
                "There's a network, but the internet isn't reachable. The problem is with your ISP \
                 or router — KVT can't help here.",
            ),
            None,
        ));
    }
    if !connected {
        out.step(
            tr("Интернет без VPN", "Internet without VPN"),
            StepState::Ok,
            tr("Интернет работает", "The internet works"),
        );
    }

    match f.server_tcp {
        Some(QuickResult::DnsFailed) => {
            out.step(
                tr("Сервер", "Server"),
                StepState::Fail,
                trf!(
                    "Адрес сервера «{server}» не находится",
                    "The address of “{server}” can't be found"
                ),
            );
            return Some(out.finish(
                Tone::Error,
                tr("Не удаётся найти адрес сервера", "Can't find the server address"),
                trf!(
                    "DNS не возвращает адрес этого сервера — провайдер мог заблокировать его домен.{}",
                    "DNS doesn't return this server's address — your ISP may have blocked its domain.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::OpenDnsCheck)),
            ));
        }
        Some(QuickResult::Unreachable) => {
            out.step(
                tr(tr("Сервер", "Server"), "Server"),
                StepState::Fail,
                trf!("«{server}» не отвечает", "“{server}” doesn't respond"),
            );
            return Some(out.finish(
                Tone::Error,
                tr("Сервер недоступен", "Server unreachable"),
                trf!(
                    "Сервер не принимает соединения: он выключен или его IP заблокирован.{}",
                    "The server doesn't accept connections: it's off or its IP is blocked.{}",
                    switch_hint(f)
                ),
                switch(f),
            ));
        }
        Some(QuickResult::Reachable { latency_ms }) => out.step(
            tr("Сервер", "Server"),
            StepState::Ok,
            trf!(
                "«{server}» отвечает, {latency_ms} мс",
                "“{server}” responds, {latency_ms} ms"
            ),
        ),
        Some(QuickResult::NotApplicable) | None => {}
    }

    if connected && f.captive {
        // Своё название шага: «Сеть» уже есть в начале списка.
        out.step(
            tr("Вход в сеть", "Network sign-in"),
            StepState::Fail,
            tr(
                "Вместо проверочного ответа пришла страница входа",
                "A sign-in page came instead of the test response",
            ),
        );
        return Some(out.finish(
            Tone::Warning,
            tr("Сеть просит войти", "The network asks you to sign in"),
            tr(
                "Похоже на Wi-Fi гостиницы, кафе или метро: сначала нужно войти на странице сети. \
                 VPN и kill switch не дают её открыть — отключите VPN, войдите и подключитесь снова.",
                "Looks like hotel, café or metro Wi-Fi: you need to sign in on the network's page first. \
                 The VPN and kill switch keep it from opening — disconnect, sign in and connect again.",
            ),
            Some(Fix::Disconnect),
        ));
    }

    if connected {
        return Some(match &f.tunnel {
            Some(Ok(trace)) => {
                let exit = trace
                    .country
                    .as_deref()
                    .map(|c| trf!(" Выход в интернет: {c}.", " Internet exit: {c}."))
                    .unwrap_or_default();
                out.step(
                    tr("Туннель", "Tunnel"),
                    StepState::Ok,
                    trf!(
                        "Данные идут через VPN, {} мс",
                        "Data goes through the VPN, {} ms",
                        trace.ms
                    ),
                );
                out.finish(
                    Tone::Ok,
                    tr("VPN работает", "VPN works"),
                    trf!(
                        "Трафик идёт через туннель.{exit} Если не открывается конкретный сайт, \
                         проверьте в «Маршрутизации», не идёт ли он напрямую.",
                        "Traffic goes through the tunnel.{exit} If a particular site doesn't open, \
                         check in “Routing” whether it goes direct."
                    ),
                    None,
                )
            }
            Some(Err(reason)) => {
                out.step(
                    tr("Туннель", "Tunnel"),
                    StepState::Fail,
                    trf!(
                        "Данные не проходят ({reason})",
                        "No data gets through ({reason})"
                    ),
                );
                out.finish(
                    Tone::Error,
                    tr("Подключение есть, но данные не идут", "Connected, but no data is flowing"),
                    trf!(
                        "Туннель поднят, но сервер не пропускает трафик: провайдер режет соединение \
                         или сервер перегружен.{}",
                        "The tunnel is up, but the server passes no traffic: your ISP is cutting the \
                         connection or the server is overloaded.{}",
                        switch_hint(f)
                    ),
                    switch(f),
                )
            }
            None => out.finish(Tone::Ok, tr("VPN подключён", "VPN connected"), "", None),
        });
    }

    None
}
