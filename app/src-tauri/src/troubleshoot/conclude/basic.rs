//! Сеть, служба, zapret и подписка: неполадки, из-за которых VPN не начнёт работать,
//! важнее всего остального.

use super::Out;
use crate::troubleshoot::{Diagnosis, Facts, Fix, StepState, Tone};
use kvt_core::i18n::tr;
use kvt_core::ipc::ServiceStatus;
use kvt_core::trf;

/// Первая стадия: `Some` — вывод готов, `None` — неполадок нет, идти дальше.
pub(super) fn run(f: &Facts, out: &mut Out) -> Option<Diagnosis> {
    if !f.network {
        out.step(
            tr("Сеть", "Network"),
            StepState::Fail,
            tr("Нет подключения к сети", "No network connection"),
        );
        return Some(out.finish(
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
        ));
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
        return Some(out.finish(
            Tone::Error,
            tr("Служба KVT не запущена", "The KVT service isn't running"),
            tr(
                "Без службы KVT не может создать туннель. Переустановите KVT или запустите службу \
                 KVTService в «Службах» Windows.",
                "Without its service KVT can't create the tunnel. Reinstall KVT or start the \
                 KVTService service in Windows Services.",
            ),
            None,
        ));
    };
    if let ServiceStatus::Failed { reason, blocked } = service {
        out.step(
            tr("Служба KVT", "KVT service"),
            StepState::Fail,
            reason.clone(),
        );
        // Текст — для службы прежней версии, которая флаг не присылает.
        let blocked = *blocked || reason.to_lowercase().contains("kill switch");
        return Some(out.finish(
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
        ));
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
        return Some(out.finish(
            Tone::Ok,
            tr("Работает zapret", "zapret is on"),
            trf!(
                "Обход DPI для YouTube и Discord включён (стратегия «{title}»). Если они всё равно \
                 не открываются, подберите стратегию автоматически — провайдеры блокируют по-разному.",
                "DPI bypass for YouTube and Discord is on (strategy “{title}”). If they still \
                 don't open, pick a strategy automatically — ISPs block in different ways."
            ),
            Some(Fix::ZapretAutoselect),
        ));
    }

    let Some(sub) = &f.subscription else {
        out.step(
            tr("Подписка", "Subscription"),
            StepState::Fail,
            tr("Подписка не добавлена", "No subscription added"),
        );
        return Some(out.finish(
            Tone::Warning,
            tr("Нет подписки", "No subscription"),
            tr(
                "Добавьте ссылку на подписку или ключ сервера, который дал провайдер VPN.",
                "Add the subscription link or server key your VPN provider gave you.",
            ),
            Some(Fix::AddSubscription),
        ));
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
        return Some(out.finish(
            Tone::Error,
            what,
            tr(
                "Продлите подписку у провайдера VPN и обновите её в KVT.",
                "Renew the subscription with your VPN provider and update it in KVT.",
            ),
            Some(Fix::RefreshSubscription),
        ));
    }
    out.step(
        tr("Подписка", "Subscription"),
        StepState::Ok,
        tr("Подписка действует", "The subscription is active"),
    );

    None
}
