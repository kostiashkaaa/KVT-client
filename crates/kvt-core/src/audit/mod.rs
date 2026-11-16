//! Аудит ПК: что на компьютере мешает VPN и zapret или пускает трафик мимо туннеля.
//!
//! Факты собирает один PowerShell-скрипт ([`SCRIPT`]) — он только читает. Здесь —
//! разбор его вывода и выводы ([`analyze`]), без обращения к системе, поэтому всё
//! покрыто тестами. Аудит сам ничего не меняет: у находки может быть исправление
//! ([`Fix`]), которое выполняется только по кнопке пользователя.
//!
//! Исправления с правами администратора выполняет служба. Пути и команды она от
//! приложения не принимает: получает [`ServiceFix`] и находит цель сама, повторив
//! сбор фактов (см. [`ServiceFix`]).
//!
//! Состав: `script` — скрипт сбора, `facts` — разбор его вывода, `finding` — находки и
//! исправления, `foreign` — что считать чужим, `leaks`, `conflicts` и `zapret` — три
//! группы проверок.

mod conflicts;
mod facts;
mod finding;
mod foreign;
mod leaks;
mod script;
#[cfg(test)]
mod tests;
mod zapret;

pub use facts::{
    parse_facts, winhttp_proxy, Adapter, Autostart, BrowserDns, Facts, FactsError, Location,
    Process, Service, SystemProxy, Teredo, STARTUP_DISABLED,
};
pub use finding::{Finding, Fix, Group, Level, ServiceFix};
pub use foreign::{
    is_foreign_zapret_service, is_vpn_process_name, is_zapret_autostart, normalize_dir, own_dirs,
    zapret_autostart_by_id, OwnDirs,
};
pub use script::{powershell_args, SCRIPT};

/// Выводы аудита. Файлы из каталогов `own` принадлежат KVT и чужими не считаются.
pub fn analyze(facts: &Facts, own: &OwnDirs) -> Vec<Finding> {
    let mut out = Vec::new();
    leaks::leaks(facts, &mut out);
    conflicts::conflicts(facts, own, &mut out);
    zapret::zapret(facts, own, &mut out);
    out
}
