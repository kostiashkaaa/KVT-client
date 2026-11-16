//! Конфиги, которые ядро уже приняло: повторное подключение к тому же серверу
//! не запускает проверку ядром ещё раз.

use super::*;

/// Сколько отпечатков принятых конфигов помнить (см. [`CheckedConfigs`]).
pub(super) const CHECKED_MAX: usize = 32;

/// Отпечатки конфигов, которые ядро уже приняло (`run -test` / `check`). Повторное
/// подключение к тому же серверу не запускает ядро лишний раз: Xray при проверке
/// читает geoip.dat на 18 МБ. Сбрасывается, когда обновились списки, — конфиг
/// ссылается на них, и новая версия может не подойти. Общий у `Supervisor` и фонового
/// обновления списков (`spawn_rules_sync`).
#[derive(Clone, Default)]
pub(super) struct CheckedConfigs(Arc<Mutex<VecDeque<u64>>>);

impl CheckedConfigs {
    pub(super) fn contains(&self, fingerprint: u64) -> bool {
        self.0.lock().is_ok_and(|c| c.contains(&fingerprint))
    }

    pub(super) fn remember(&self, fingerprint: u64) {
        if let Ok(mut c) = self.0.lock() {
            if c.len() >= CHECKED_MAX {
                c.pop_front();
            }
            c.push_back(fingerprint);
        }
    }

    pub(super) fn forget(&self) {
        if let Ok(mut c) = self.0.lock() {
            c.clear();
        }
    }
}

pub(super) fn config_fingerprint(core: CoreKind, config: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    format!("{core:?}").hash(&mut h);
    config.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_configs_are_remembered_and_forgotten() {
        let a = config_fingerprint(CoreKind::Xray, b"{\"a\":1}");
        let b = config_fingerprint(CoreKind::SingBox, b"{\"a\":1}");
        assert_ne!(a, b, "отпечаток зависит от ядра");
        let checked = CheckedConfigs::default();
        assert!(!checked.contains(a));
        checked.remember(a);
        assert!(checked.contains(a) && !checked.contains(b));
        for i in 0..CHECKED_MAX as u64 {
            checked.remember(i);
        }
        assert!(!checked.contains(a), "старые отпечатки вытесняются");
        checked.remember(b);
        let shared = checked.clone();
        shared.forget();
        assert!(
            !checked.contains(b),
            "фоновое обновление списков сбрасывает общий кэш"
        );
    }
}
