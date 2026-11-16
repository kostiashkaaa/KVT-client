//! Остатки других сборок zapret: службы, процессы и записи автозагрузки.

use super::foreign::{is_foreign_zapret_service, is_own, is_zapret_autostart};
use super::{Autostart, Facts, Finding, Fix, Group, Level, OwnDirs, Process, Service, ServiceFix};
use crate::i18n::tr;
use crate::trf;

pub(super) fn zapret(facts: &Facts, own: &OwnDirs, out: &mut Vec<Finding>) {
    use Group::Zapret;
    let services: Vec<&Service> = facts
        .services
        .iter()
        .filter(|s| is_foreign_zapret_service(s, own))
        .collect();
    let processes: Vec<&Process> = facts
        .processes
        .iter()
        .filter(|p| {
            let n = p.name.to_lowercase();
            (n == "winws" || n == "goodbyedpi") && !is_own(&p.path, own)
        })
        .collect();
    let autostart: Vec<&Autostart> = facts
        .autostart
        .iter()
        .filter(|a| is_zapret_autostart(a, own))
        .collect();

    if services.is_empty() && processes.is_empty() && autostart.is_empty() {
        out.push(Finding::new(
            Zapret,
            Level::Ok,
            tr("Другие сборки zapret", "Other zapret builds"),
            tr(
                "Не найдены: ни служб, ни запущенных winws, ни автозапуска.",
                "None found: no services, no running winws, no autostart.",
            ),
        ));
        return;
    }

    let running_service = services
        .iter()
        .any(|s| s.state.eq_ignore_ascii_case("running"));
    if running_service || !processes.is_empty() {
        let mut names: Vec<String> = processes
            .iter()
            .map(|p| format!("{}.exe", p.name))
            .collect();
        names.extend(
            services
                .iter()
                .filter(|s| s.state.eq_ignore_ascii_case("running"))
                .map(|s| trf!("служба {}", "service {}", s.name)),
        );
        names.dedup();
        out.push(
            Finding::new(
                Zapret,
                Level::Warning,
                tr(
                    "Работает другая сборка zapret",
                    "Another zapret build is running",
                ),
                trf!(
                    "{}. Два обхода DPI одновременно перехватывают одни и те же пакеты — \
                     режимы «Гибрид» и «Zapret» в KVT работают неправильно.",
                    "{}. Two DPI bypasses intercept the same packets at once — \
                     KVT's Hybrid and Zapret modes don't work right.",
                    names.join(", ")
                ),
            )
            .fix(Fix::StopZapret),
        );
    }

    for s in services
        .iter()
        .filter(|s| s.start_mode.eq_ignore_ascii_case("auto"))
    {
        out.push(
            Finding::new(
                Zapret,
                Level::Warning,
                trf!(
                    "Служба {} запускается вместе с Windows",
                    "Service {} starts with Windows",
                    s.name
                ),
                trf!(
                    "{} стартует при каждом включении компьютера и мешает zapret в KVT. \
                     Исправление остановит её и переведёт в ручной запуск — ничего не удаляется.",
                    "{} starts every time the computer turns on and interferes with zapret in KVT. \
                     The fix stops it and sets it to manual start — nothing is deleted.",
                    if s.display_name.is_empty() {
                        &s.name
                    } else {
                        &s.display_name
                    }
                ),
            )
            .fix(Fix::Service(ServiceFix::DisableZapretService {
                name: s.name.clone(),
            })),
        );
    }

    for a in autostart {
        let id = a.id();
        let fix = if a.location.machine_wide() {
            Fix::Service(ServiceFix::DisableAutostart { id })
        } else {
            Fix::DisableUserAutostart { id }
        };
        out.push(
            Finding::new(
                Zapret,
                Level::Warning,
                trf!("Автозапуск zapret: {}", "zapret autostart: {}", a.name),
                trf!(
                    "Запись в разделе «{}» запускает другую сборку zapret при входе в Windows. \
                     Исправление отключит её так же, как «Отключить» в «Диспетчере задач».",
                    "An entry in “{}” starts another zapret build when you sign in to Windows. \
                     The fix disables it the same way as “Disable” in Task Manager.",
                    a.location.title()
                ),
            )
            .fix(fix),
        );
    }
}
