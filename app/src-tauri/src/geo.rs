//! Страна сервера по адресу-IP: флаг для названий без эмодзи. База стран вшита в
//! `kvt.exe` (`presets/dbip-country.bin`, DB-IP Country Lite, CC BY 4.0 — атрибуция
//! в «О программе» и `THIRD-PARTY-NOTICES.md`); обновляет её
//! `scripts/update-dbip.ps1` перед выпуском. Поиск локальный, сети нет, поэтому
//! доменные адреса флага не получают: им нужен был бы DNS.

use kvt_core::geo::CountryDb;
use std::net::IpAddr;
use std::sync::OnceLock;

static BUNDLED: &[u8] = include_bytes!("../../../presets/dbip-country.bin");

/// База, разобранная и проверенная один раз при первом обращении. Не разобралась —
/// запись в журнал, дальше флагов по адресу просто нет (в релизе паника — `abort`).
fn database() -> Option<&'static CountryDb<'static>> {
    static DB: OnceLock<Option<CountryDb<'static>>> = OnceLock::new();
    DB.get_or_init(|| match CountryDb::parse(BUNDLED) {
        Ok(db) => Some(db),
        Err(e) => {
            tracing::warn!(error = %e, "база стран по IP не разобралась — флаги по адресу выключены");
            None
        }
    })
    .as_ref()
}

/// Флаг (`"nl"`) по адресу сервера: только для IP-адреса (в скобках у IPv6 тоже) и
/// только если страна известна и для неё есть картинка. Адрес — данные сервера:
/// наружу уходит один код страны, в журнал адрес не пишется.
pub(crate) fn address_flag(address: &str) -> Option<String> {
    let ip: IpAddr = address.trim().trim_matches(['[', ']']).parse().ok()?;
    kvt_core::flag::from_country(database()?.country(ip)?)
}

#[cfg(test)]
mod tests {
    use super::address_flag;

    #[test]
    fn ip_address_gives_a_flag() {
        assert_eq!(address_flag("8.8.8.8").as_deref(), Some("us"));
        assert_eq!(address_flag("77.88.8.8").as_deref(), Some("ru"));
        assert_eq!(address_flag(" 8.8.8.8 ").as_deref(), Some("us"));
        assert_eq!(address_flag("[2a02:6b8::1]").as_deref(), Some("ru"));
        assert_eq!(address_flag("::ffff:8.8.8.8").as_deref(), Some("us"));
    }

    #[test]
    fn domains_private_and_garbage_give_no_flag() {
        // Домен — без DNS страну не узнать.
        assert_eq!(address_flag("example.com"), None);
        assert_eq!(address_flag("nl.example.com"), None);
        // Частные и служебные адреса.
        for ip in ["192.168.1.10", "10.0.0.1", "127.0.0.1", "::1", "0.0.0.0"] {
            assert_eq!(address_flag(ip), None, "{ip}");
        }
        for text in [
            "",
            " ",
            "[]",
            "999.1.1.1",
            "1.2.3",
            "8.8.8.8:443",
            "не адрес",
        ] {
            assert_eq!(address_flag(text), None, "{text}");
        }
    }
}
