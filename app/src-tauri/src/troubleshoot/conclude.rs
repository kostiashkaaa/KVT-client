//! Выводы: из собранных фактов — шаги от простого к сложному и один итог. Без обращения
//! к сети и состоянию окна, поэтому покрыто тестами.

use super::{Diagnosis, Facts, Fix, ProbeFact, Step, StepState, Tone};
use kvt_core::i18n::tr;
use kvt_core::ipc::ServiceStatus;
use kvt_core::probe::Verdict;
use kvt_core::tester::QuickResult;
use kvt_core::trf;

struct Out {
    steps: Vec<Step>,
}

impl Out {
    fn step(&mut self, title: &'static str, state: StepState, detail: impl Into<String>) {
        self.steps.push(Step {
            title,
            state,
            detail: detail.into(),
        });
    }

    fn finish(
        self,
        tone: Tone,
        title: impl Into<String>,
        detail: impl Into<String>,
        fix: Option<Fix>,
    ) -> Diagnosis {
        Diagnosis {
            tone,
            title: title.into(),
            detail: detail.into(),
            steps: self.steps,
            fix,
        }
    }
}

pub(super) fn switch(f: &Facts) -> Option<Fix> {
    f.alternative
        .clone()
        .map(|(key, name)| Fix::SwitchServer { key, name })
}

pub(super) fn switch_hint(f: &Facts) -> String {
    match &f.alternative {
        Some((_, name)) => trf!(
            " Можно переключиться на «{name}».",
            " You can switch to “{name}”."
        ),
        None => tr(
            " Рабочей замены в подписке не нашлось — обновите подписку или напишите в поддержку провайдера VPN.",
            " No working replacement in the subscription — update it or contact your VPN provider's support.",
        )
        .into(),
    }
}

pub fn conclude(f: &Facts) -> Diagnosis {
    let mut out = Out { steps: Vec::new() };

    if !f.network {
        out.step(
            tr("Сеть", "Network"),
            StepState::Fail,
            tr("Нет подключения к сети", "No network connection"),
        );
        return out.finish(
            Tone::Error,
            tr(
                "Компьютер не подключён к сети",
                "The computer isn't connected to a network",
            ),
            tr(
                "Проверьте Wi-Fi или кабель. VPN заработает, как только появится сеть.",
                "Check Wi-Fi or the cable. The VPN will work as soon as there's a network.",
            ),
            None,
        );
    }
    out.step(
        tr("Сеть", "Network"),
        StepState::Ok,
        tr("Подключение к сети есть", "Network connection is up"),
    );

    let Some(service) = &f.service else {
        out.step(
            tr("Служба KVT", "KVT service"),
            StepState::Fail,
            tr("Служба не отвечает", "The service doesn't respond"),
        );
        return out.finish(
            Tone::Error,
            tr("Служба KVT не запущена", "The KVT service isn't running"),
            tr(
                "Без службы KVT не может создать туннель. Переустановите KVT или запустите службу \
                 KVTService в «Службах» Windows.",
                "Without its service KVT can't create the tunnel. Reinstall KVT or start the \
                 KVTService service in Windows Services.",
            ),
            None,
        );
    };
    if let ServiceStatus::Failed { reason, blocked } = service {
        out.step(
            tr("Служба KVT", "KVT service"),
            StepState::Fail,
            reason.clone(),
        );
        // Текст — для службы прежней версии, которая флаг не присылает.
        let blocked = *blocked || reason.to_lowercase().contains("kill switch");
        return out.finish(
            Tone::Error,
            tr("Соединение прервалось", "Connection lost"),
            if blocked {
                tr(
                    "Ядро остановилось, и kill switch закрыл интернет, чтобы ничего не ушло мимо \
                     туннеля. Отключитесь, чтобы вернуть интернет, или подключитесь снова.",
                    "The core stopped, and the kill switch blocked the internet so nothing leaks \
                     outside the tunnel. Disconnect to restore the internet, or connect again.",
                )
            } else {
                tr(
                    "Ядро VPN остановилось. Попробуйте подключиться снова.",
                    "The VPN core stopped. Try connecting again.",
                )
            },
            Some(if blocked {
                Fix::Disconnect
            } else {
                Fix::Connect
            }),
        );
    }
    out.step(
        tr("Служба KVT", "KVT service"),
        StepState::Ok,
        tr("Служба работает", "The service is running"),
    );

    if let ServiceStatus::Zapret { strategy } = service {
        let title = kvt_core::zapret::title(strategy);
        out.step(
            "Zapret",
            StepState::Ok,
            trf!(
                "Работает, стратегия «{title}»",
                "Working, strategy “{title}”"
            ),
        );
        return out.finish(
            Tone::Ok,
            tr("Работает zapret", "zapret is on"),
            trf!(
                "Обход DPI для YouTube и Discord включён (стратегия «{title}»). Если они всё равно \
                 не открываются, подберите стратегию автоматически — провайдеры блокируют по-разному.",
                "DPI bypass for YouTube and Discord is on (strategy “{title}”). If they still \
                 don't open, pick a strategy automatically — ISPs block in different ways."
            ),
            Some(Fix::ZapretAutoselect),
        );
    }

    let Some(sub) = &f.subscription else {
        out.step(
            tr("Подписка", "Subscription"),
            StepState::Fail,
            tr("Подписка не добавлена", "No subscription added"),
        );
        return out.finish(
            Tone::Warning,
            tr("Нет подписки", "No subscription"),
            tr(
                "Добавьте ссылку на подписку или ключ сервера, который дал провайдер VPN.",
                "Add the subscription link or server key your VPN provider gave you.",
            ),
            Some(Fix::AddSubscription),
        );
    };
    if sub.expired || sub.exhausted {
        let what = if sub.expired {
            tr("Срок подписки закончился", "The subscription has expired")
        } else {
            tr(
                "Трафик подписки израсходован",
                "The subscription's traffic is used up",
            )
        };
        out.step(tr("Подписка", "Subscription"), StepState::Fail, what);
        return out.finish(
            Tone::Error,
            what,
            tr(
                "Продлите подписку у провайдера VPN и обновите её в KVT.",
                "Renew the subscription with your VPN provider and update it in KVT.",
            ),
            Some(Fix::RefreshSubscription),
        );
    }
    out.step(
        tr("Подписка", "Subscription"),
        StepState::Ok,
        tr("Подписка действует", "The subscription is active"),
    );

    let Some(server) = &f.server else {
        out.step(
            tr("Сервер", "Server"),
            StepState::Fail,
            tr("Сервер не выбран", "No server selected"),
        );
        return out.finish(
            Tone::Warning,
            tr("Не выбран сервер", "No server selected"),
            tr(
                "Выберите сервер в списке на главной.",
                "Pick a server from the list on the home page.",
            ),
            None,
        );
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
        return out.finish(
            Tone::Error,
            tr("Интернет не работает даже без VPN", "The internet doesn't work even without the VPN"),
            tr(
                "Сеть есть, но в интернет выйти не получается. Проблема у провайдера или роутера — \
                 KVT здесь не поможет.",
                "There's a network, but the internet isn't reachable. The problem is with your ISP \
                 or router — KVT can't help here.",
            ),
            None,
        );
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
            return out.finish(
                Tone::Error,
                tr("Не удаётся найти адрес сервера", "Can't find the server address"),
                trf!(
                    "DNS не возвращает адрес этого сервера — провайдер мог заблокировать его домен.{}",
                    "DNS doesn't return this server's address — your ISP may have blocked its domain.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::OpenDnsCheck)),
            );
        }
        Some(QuickResult::Unreachable) => {
            out.step(
                tr(tr("Сервер", "Server"), "Server"),
                StepState::Fail,
                trf!("«{server}» не отвечает", "“{server}” doesn't respond"),
            );
            return out.finish(
                Tone::Error,
                tr("Сервер недоступен", "Server unreachable"),
                trf!(
                    "Сервер не принимает соединения: он выключен или его IP заблокирован.{}",
                    "The server doesn't accept connections: it's off or its IP is blocked.{}",
                    switch_hint(f)
                ),
                switch(f),
            );
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
        return out.finish(
            Tone::Warning,
            tr("Сеть просит войти", "The network asks you to sign in"),
            tr(
                "Похоже на Wi-Fi гостиницы, кафе или метро: сначала нужно войти на странице сети. \
                 VPN и kill switch не дают её открыть — отключите VPN, войдите и подключитесь снова.",
                "Looks like hotel, café or metro Wi-Fi: you need to sign in on the network's page first. \
                 The VPN and kill switch keep it from opening — disconnect, sign in and connect again.",
            ),
            Some(Fix::Disconnect),
        );
    }

    if connected {
        return match &f.tunnel {
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
        };
    }

    match &f.probe {
        Some(ProbeFact::Done(Verdict::Works)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Ok,
                Verdict::Works.message(),
            );
            out.finish(
                Tone::Ok,
                tr("Сервер работает — можно подключаться", "The server works — you can connect"),
                tr(
                    "Через этот сервер данные проходят. Если после подключения сайты не открываются, \
                     запустите проверку ещё раз при включённом VPN.",
                    "Data gets through this server. If sites don't open after connecting, \
                     run the check again with the VPN on.",
                ),
                Some(Fix::Connect),
            )
        }
        Some(ProbeFact::Done(Verdict::Slow)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Warning,
                Verdict::Slow.message(),
            );
            out.finish(
                Tone::Warning,
                tr(
                    "Сервер работает, но медленно",
                    "The server works, but slowly",
                ),
                trf!(
                    "Подключиться можно, но страницы будут открываться с задержкой.{}",
                    "You can connect, but pages will open with a delay.{}",
                    switch_hint(f)
                ),
                switch(f).or(Some(Fix::Connect)),
            )
        }
        Some(ProbeFact::Done(verdict)) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Fail,
                verdict.message(),
            );
            let title = match verdict {
                Verdict::TlsFrozen | Verdict::DataFrozen => tr(
                    "Провайдер блокирует этот сервер",
                    "Your ISP is blocking this server",
                ),
                Verdict::Rejected => tr(
                    "Сервер отклоняет подключение",
                    "The server rejects the connection",
                ),
                Verdict::ConfigError => tr("Сервер не поддерживается", "Server not supported"),
                Verdict::DnsFailed => tr(
                    "Не удаётся найти адрес сервера",
                    "Can't find the server address",
                ),
                _ => tr("Сервер недоступен", "Server unreachable"),
            };
            out.finish(
                Tone::Error,
                title,
                format!("{}.{}", verdict.message(), switch_hint(f)),
                switch(f),
            )
        }
        Some(ProbeFact::Postponed) => {
            out.step(
                tr("Проверка сервера", "Server check"),
                StepState::Warning,
                tr(
                    "Отложена: к этому серверу недавно подключались",
                    "Postponed: this server was connected to recently",
                ),
            );
            out.finish(
                Tone::Warning,
                tr("Повторите проверку через пару минут", "Repeat the check in a couple of minutes"),
                tr(
                    "Частые подключения к одному серверу заметны провайдеру, поэтому KVT выдерживает \
                     паузу. Сервер отвечает — попробуйте подключиться.",
                    "Frequent connections to one server are noticeable to your ISP, so KVT waits. \
                     The server responds — try connecting.",
                ),
                Some(Fix::Connect),
            )
        }
        None => out.finish(
            Tone::Ok,
            tr("Явных проблем не найдено", "No obvious problems found"),
            tr("Попробуйте подключиться.", "Try connecting."),
            Some(Fix::Connect),
        ),
    }
}
