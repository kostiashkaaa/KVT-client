//! Сеть со страницей входа (отель, кафе, метро). Проверка по образцу Windows
//! NCSI: маленький HTTP-запрос с заранее известным ответом. Если вместо него
//! пришло перенаправление или чужая страница — сеть просит войти.
//!
//! Адрес — IP, а не имя: при подключённом VPN системный DNS идёт в туннель,
//! который в такой сети как раз не работает.

use crate::ipc::Captive;

/// Ответ Cloudflare `/cdn-cgi/trace` — несколько строк `ключ=значение`.
pub const PROBE_URLS: &[&str] = &[
    "http://1.1.1.1/cdn-cgi/trace",
    "http://1.0.0.1/cdn-cgi/trace",
];

/// Итог по ответу на проверочный запрос (статус и тело).
pub fn classify(status: u16, body: &str) -> Captive {
    let expected = status == 200
        && body.lines().any(|l| l.starts_with("fl="))
        && body.lines().any(|l| l.starts_with("colo="));
    if expected {
        Captive::Online
    } else {
        Captive::Portal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_answer_means_online() {
        let body = "fl=12f\nh=1.1.1.1\nip=203.0.113.7\nts=1\nvisit_scheme=http\ncolo=AMS\n";
        assert_eq!(classify(200, body), Captive::Online);
    }

    #[test]
    fn redirect_or_foreign_page_means_portal() {
        assert_eq!(classify(302, ""), Captive::Portal);
        assert_eq!(
            classify(511, "Network Authentication Required"),
            Captive::Portal
        );
        assert_eq!(
            classify(
                200,
                "<html><form action=/login>Wi-Fi гостиницы</form></html>"
            ),
            Captive::Portal
        );
    }
}
