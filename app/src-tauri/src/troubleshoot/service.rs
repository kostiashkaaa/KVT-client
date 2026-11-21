//! «Почему не работает?» про сервис: ✗ на плитке («YouTube — не открывается») ведёт сюда.
//!
//! Сначала общие неполадки (сеть, служба, подписка, сервер, туннель): если они есть,
//! сервис — лишь их следствие, и ответ про них, а сервис — последний шаг. Иначе ответ
//! про сам сервис по тому, каким путём идёт его трафик (`Via`) и что показала проба
//! (`Cause`). Без обращения к сети и состоянию окна — покрыто тестами; отдельно от
//! `conclude`, который отвечает на общий вопрос.

use super::conclude::{conclude, switch, switch_hint};
use super::{Diagnosis, Facts, Fix, ServiceFact, Step, StepState, Tone};
use kvt_core::i18n::tr;
use kvt_core::ipc::ServiceStatus;
use kvt_core::services::{Cause, Health, Via};
use kvt_core::trf;

struct Answer {
    tone: Tone,
    title: String,
    detail: String,
    fix: Option<Fix>,
}

pub fn conclude_for(f: &Facts, s: &ServiceFact) -> Diagnosis {
    let mut d = conclude(f);
    // Общая неполадка объясняет и сервис: ответ про неё, а сервис — шаг в конце.
    let general = d.tone != Tone::Ok;
    d.steps.push(step(s, general));
    if general || s.health == Health::Works {
        return d;
    }
    let a = answer(f, s);
    Diagnosis {
        tone: a.tone,
        title: a.title,
        detail: a.detail,
        steps: d.steps,
        fix: a.fix,
    }
}

/// Шаг про сам сервис. `general` — выше нашлась общая неполадка: у плохого сервиса это
/// пометка «следствие».
fn step(s: &ServiceFact, general: bool) -> Step {
    let name = &s.name;
    // После двоеточия — со строчной: «YouTube: соединение обрывается…».
    let message = s.health.message();
    let mut chars = message.chars();
    let what: String = chars
        .next()
        .map(|first| first.to_lowercase().chain(chars).collect())
        .unwrap_or_default();
    let state = match s.health {
        Health::Works => StepState::Ok,
        Health::Slow => StepState::Warning,
        Health::Down(_) => StepState::Fail,
    };
    let detail = if general && s.health != Health::Works {
        trf!(
            "{name}: {what} — скорее всего, из-за неполадки выше",
            "{name}: {what} — most likely because of the problem above"
        )
    } else {
        trf!("{name}: {what}", "{name}: {what}")
    };
    Step {
        title: tr("Сервис", "Service"),
        state,
        detail,
    }
}

/// Общих неполадок нет: что не так с самим сервисом.
fn answer(f: &Facts, s: &ServiceFact) -> Answer {
    let name = &s.name;
    let slow = s.health == Health::Slow;
    let tone = if slow { Tone::Warning } else { Tone::Error };
    let title = if slow {
        trf!("{name} открывается медленно", "{name} opens slowly")
    } else {
        trf!("{name} не открывается", "{name} doesn't open")
    };
    // Подключение ещё идёт: прежний итог плиток уже не про него.
    if matches!(f.service, Some(ServiceStatus::Connecting)) {
        return Answer {
            tone: Tone::Warning,
            title,
            detail: tr(
                "Идёт подключение — повторите проверку, когда оно закончится.",
                "Connecting is in progress — check again when it's done.",
            )
            .into(),
            fix: None,
        };
    }
    let say = |detail: String, fix: Option<Fix>| Answer {
        tone,
        title: title.clone(),
        detail,
        fix,
    };
    let connected = matches!(f.service, Some(ServiceStatus::Connected { .. }));
    let zapret = matches!(f.service, Some(ServiceStatus::Zapret { .. }));

    // Адрес не нашёлся: каким бы путём сервис ни шёл, дело в DNS (кроме закрытого правилом).
    if s.health == Health::Down(Cause::Dns) && s.via != Via::Blocked {
        return if s.via == Via::Vpn || (s.via == Via::Proxy && connected) {
            say(
                trf!(
                    "Адрес {name} не находится даже через туннель: DNS внутри туннеля не отвечает.{}",
                    "The address of {name} can't be found even through the tunnel: DNS inside the tunnel doesn't respond.{}",
                    switch_hint(f)
                ),
                switch(f),
            )
        } else {
            say(
                trf!(
                    "Адрес {name} не находится: DNS не отвечает или подменяет ответ. Проверьте DNS-серверы.",
                    "The address of {name} can't be found: DNS doesn't respond or spoofs the answer. Check the DNS servers."
                ),
                Some(Fix::OpenDnsCheck),
            )
        };
    }

    match s.via {
        // Закрыт правилом маршрутизации — это выбор пользователя, а не сбой.
        Via::Blocked => Answer {
            tone: Tone::Error,
            title: trf!("{name} не открывается", "{name} doesn't open"),
            detail: trf!(
                "В «Маршрутизации» трафик к {name} закрыт правилом. Измените правило, если сервис нужен.",
                "A routing rule in “Routing” blocks traffic to {name}. Change the rule if you need the service."
            ),
            fix: None,
        },
        Via::Direct if connected => say(
            trf!(
                "{name} идёт напрямую, мимо VPN — так настроена маршрутизация, — а провайдер его блокирует или замедляет. В «Маршрутизации» пустите сервис через VPN.",
                "{name} goes directly, bypassing the VPN — that's how routing is set — and your ISP blocks or throttles it. In “Routing”, send the service through the VPN."
            ),
            None,
        ),
        Via::Direct if zapret => say(
            trf!(
                "Режим «Zapret» работает без VPN: {name} в нём идёт напрямую, и zapret его не обрабатывает. Включите «VPN» или «Гибрид».",
                "Zapret mode runs without a VPN: {name} goes directly and zapret doesn't handle it. Switch to VPN or Hybrid."
            ),
            None,
        ),
        Via::Direct => say(
            trf!(
                "Сейчас ничего не подключено, и {name} открывался напрямую — провайдер его блокирует или замедляет. Подключитесь и проверьте снова.",
                "Nothing is connected right now, and {name} was opened directly — your ISP blocks or throttles it. Connect and check again."
            ),
            Some(Fix::Connect),
        ),
        Via::Zapret => say(
            trf!(
                "{name} идёт через zapret, но выбранная стратегия, похоже, не подходит вашему провайдеру: провайдеры блокируют по-разному. Подберите стратегию автоматически.",
                "{name} goes through zapret, but the selected strategy doesn't seem to suit your ISP: ISPs block in different ways. Pick a strategy automatically."
            ),
            Some(Fix::ZapretAutoselect),
        ),
        Via::Vpn => say(
            trf!(
                "Туннель работает, но {name} отвечает плохо: сервис мог закрыть адрес этого сервера или сервер перегружен.{}",
                "The tunnel works, but {name} responds badly: the service may have blocked this server's address, or the server is overloaded.{}",
                switch_hint(f)
            ),
            switch(f),
        ),
        Via::Proxy if connected => say(
            trf!(
                "{name} ходит через прокси KVT, а прокси через VPN не достучался до серверов сервиса: через этот сервер они не открываются.{}",
                "{name} goes through the KVT proxy, and the proxy couldn't reach the service's servers through the VPN: they don't open through this server.{}",
                switch_hint(f)
            ),
            switch(f),
        ),
        Via::Proxy if zapret => say(
            trf!(
                "{name} ходит через прокси KVT, а прокси не достучался до серверов сервиса — похоже, стратегия zapret не подходит вашему провайдеру. Подберите её автоматически.",
                "{name} goes through the KVT proxy, and the proxy couldn't reach the service's servers — the zapret strategy probably doesn't suit your ISP. Pick one automatically."
            ),
            Some(Fix::ZapretAutoselect),
        ),
        Via::Proxy => say(
            trf!(
                "{name} ходит через прокси KVT, а прокси не достучался до серверов сервиса. Проверьте блок Telegram на странице «Zapret».",
                "{name} goes through the KVT proxy, and the proxy couldn't reach the service's servers. Check the Telegram block on the “Zapret” page."
            ),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Trace;
    use crate::troubleshoot::tests::base;
    use kvt_core::core_select::CoreKind;
    use kvt_core::i18n::{with, Lang};

    fn svc(via: Via, health: Health) -> ServiceFact {
        ServiceFact {
            name: "YouTube".into(),
            via,
            health,
        }
    }

    const CUT: Health = Health::Down(Cause::Cut);

    /// VPN подключён, данные через туннель идут: общих неполадок нет.
    fn vpn_ok() -> Facts {
        let mut f = base();
        f.service = Some(ServiceStatus::Connected {
            core: CoreKind::Xray,
        });
        f.probe = None;
        f.tunnel = Some(Ok(Trace {
            country: Some("NL".into()),
            ms: 90,
        }));
        f
    }

    fn zapret_on() -> Facts {
        let mut f = base();
        f.service = Some(ServiceStatus::Zapret {
            strategy: "general".into(),
        });
        f
    }

    #[test]
    fn a_general_problem_explains_the_service() {
        let mut f = base();
        f.service = None;
        let d = conclude_for(&f, &svc(Via::Vpn, CUT));
        // Ответ про службу KVT, а сервис — последний шаг и помечен как следствие.
        assert_eq!(d.title, "Служба KVT не запущена");
        let last = d.steps.last().unwrap();
        assert_eq!(last.title, "Сервис");
        assert_eq!(last.state, StepState::Fail);
        assert!(
            last.detail.contains("из-за неполадки выше"),
            "{}",
            last.detail
        );
        assert!(
            last.detail.starts_with("YouTube: соединение обрывается"),
            "{}",
            last.detail
        );
        assert_eq!(d.tone, Tone::Error);
    }

    #[test]
    fn tunnel_without_data_is_the_answer_for_a_service_behind_it() {
        let mut f = vpn_ok();
        f.tunnel = Some(Err("нет ответа".into()));
        let d = conclude_for(&f, &svc(Via::Vpn, CUT));
        assert_eq!(d.title, "Подключение есть, но данные не идут");
        assert!(matches!(d.fix, Some(Fix::SwitchServer { .. })));
    }

    #[test]
    fn service_behind_a_working_vpn_offers_another_server() {
        let d = conclude_for(&vpn_ok(), &svc(Via::Vpn, CUT));
        assert_eq!(d.title, "YouTube не открывается");
        assert_eq!(d.tone, Tone::Error);
        assert!(matches!(&d.fix, Some(Fix::SwitchServer { key, .. }) if key == "k3"));
        assert!(
            d.detail.contains("Можно переключиться на «DE»"),
            "{}",
            d.detail
        );
        // Шаги общей проверки остались, сервис — последним.
        assert_eq!(d.steps.last().unwrap().title, "Сервис");
        assert!(d.steps.len() > 2);
    }

    #[test]
    fn without_a_replacement_there_is_no_switch() {
        let mut f = vpn_ok();
        f.alternative = None;
        let d = conclude_for(&f, &svc(Via::Vpn, Health::Down(Cause::Unreachable)));
        assert_eq!(d.fix, None);
        assert!(d.detail.contains("Рабочей замены"), "{}", d.detail);
    }

    #[test]
    fn slow_service_is_a_warning() {
        let d = conclude_for(&vpn_ok(), &svc(Via::Vpn, Health::Slow));
        assert_eq!(d.tone, Tone::Warning);
        assert_eq!(d.title, "YouTube открывается медленно");
        assert_eq!(d.steps.last().unwrap().state, StepState::Warning);
    }

    #[test]
    fn working_service_keeps_the_general_answer() {
        let general = conclude(&vpn_ok());
        let d = conclude_for(&vpn_ok(), &svc(Via::Vpn, Health::Works));
        assert_eq!(
            (d.tone, &d.title, &d.fix),
            (general.tone, &general.title, &general.fix)
        );
        let last = d.steps.last().unwrap();
        assert_eq!(last.state, StepState::Ok);
        assert!(!last.detail.contains("неполадки"), "{}", last.detail);
    }

    #[test]
    fn direct_path_under_a_vpn_points_at_routing() {
        let d = conclude_for(&vpn_ok(), &svc(Via::Direct, CUT));
        assert_eq!(d.fix, None);
        assert!(d.detail.contains("«Маршрутизации»"), "{}", d.detail);
        assert!(d.detail.contains("мимо VPN"), "{}", d.detail);
    }

    #[test]
    fn nothing_connected_offers_to_connect() {
        let d = conclude_for(&base(), &svc(Via::Direct, CUT));
        assert_eq!(d.fix, Some(Fix::Connect));
        assert!(d.detail.contains("ничего не подключено"), "{}", d.detail);
        // Идёт подключение — ждём, а не советуем подключаться ещё раз.
        let mut f = base();
        f.service = Some(ServiceStatus::Connecting);
        let d = conclude_for(&f, &svc(Via::Direct, CUT));
        assert_eq!((d.tone, d.fix), (Tone::Warning, None));
    }

    #[test]
    fn zapret_path_offers_a_strategy() {
        let d = conclude_for(&zapret_on(), &svc(Via::Zapret, CUT));
        assert_eq!(d.fix, Some(Fix::ZapretAutoselect));
        assert_eq!(d.title, "YouTube не открывается");
        // Сервис, который zapret не обрабатывает, стратегией не лечится.
        let d = conclude_for(&zapret_on(), &svc(Via::Direct, CUT));
        assert_eq!(d.fix, None);
        assert!(d.detail.contains("«Гибрид»"), "{}", d.detail);
    }

    #[test]
    fn proxy_path_depends_on_what_is_running() {
        let d = conclude_for(&vpn_ok(), &svc(Via::Proxy, CUT));
        assert!(matches!(d.fix, Some(Fix::SwitchServer { .. })));
        let d = conclude_for(&zapret_on(), &svc(Via::Proxy, CUT));
        assert_eq!(d.fix, Some(Fix::ZapretAutoselect));
        let d = conclude_for(&base(), &svc(Via::Proxy, CUT));
        assert_eq!(d.fix, None);
        assert!(d.detail.contains("«Zapret»"), "{}", d.detail);
    }

    #[test]
    fn blocked_by_a_rule_is_not_a_fault() {
        let d = conclude_for(
            &vpn_ok(),
            &svc(Via::Blocked, Health::Down(Cause::Unreachable)),
        );
        assert_eq!(d.fix, None);
        assert!(d.detail.contains("правилом"), "{}", d.detail);
    }

    #[test]
    fn address_not_found_is_about_dns() {
        let dns = Health::Down(Cause::Dns);
        let d = conclude_for(&base(), &svc(Via::Direct, dns));
        assert_eq!(d.fix, Some(Fix::OpenDnsCheck));
        let d = conclude_for(&zapret_on(), &svc(Via::Zapret, dns));
        assert_eq!(d.fix, Some(Fix::OpenDnsCheck));
        // Через туннель DNS шифруется и идёт внутри него — проверка DNS окна тут не поможет.
        let d = conclude_for(&vpn_ok(), &svc(Via::Vpn, dns));
        assert!(matches!(d.fix, Some(Fix::SwitchServer { .. })));
        assert!(d.detail.contains("внутри туннеля"), "{}", d.detail);
    }

    #[test]
    fn step_titles_do_not_repeat() {
        let d = conclude_for(&vpn_ok(), &svc(Via::Vpn, CUT));
        let mut titles: Vec<_> = d.steps.iter().map(|s| s.title).collect();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(titles.len(), d.steps.len());
    }

    #[test]
    fn english_texts() {
        let d = with(Lang::En, || conclude_for(&vpn_ok(), &svc(Via::Vpn, CUT)));
        assert_eq!(d.title, "YouTube doesn't open");
        assert_eq!(d.steps.last().unwrap().title, "Service");
        assert!(d.detail.contains("You can switch to “DE”"), "{}", d.detail);
        let d = with(Lang::En, || {
            conclude_for(&vpn_ok(), &svc(Via::Vpn, Health::Slow))
        });
        assert_eq!(d.title, "YouTube opens slowly");
        let d = with(Lang::En, || conclude_for(&vpn_ok(), &svc(Via::Direct, CUT)));
        assert!(d.detail.contains("“Routing”"), "{}", d.detail);
    }
}
