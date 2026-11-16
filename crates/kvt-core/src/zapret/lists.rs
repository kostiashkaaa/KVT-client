//! Пользовательские списки zapret (`*-user.txt`): домены, которые идут через zapret, и
//! адреса VPN-серверов, которые winws не трогает.

use super::ZapretError;

/// Домен для списка winws: только буквы, цифры, точки и дефисы, без переводов строк.
pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && !d.starts_with('.')
        && !d.ends_with('.')
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Заглушка Flowseal: пустой список winws понимает как «всё», поэтому пустым он не бывает.
pub const EMPTY_HOSTLIST: &str = "domain.example.abc";
pub const EMPTY_IPSET: &str = "203.0.113.113/32";

/// Пользовательские списки (`*-user.txt`), которые стратегии Flowseal подключают сами.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLists {
    /// Домены, которые идут через zapret (из RoutingPlan).
    pub general: String,
    /// Домены VPN-серверов — winws их не трогает.
    pub exclude: String,
    /// IP VPN-серверов — winws их не трогает.
    pub ipset_exclude: String,
}

/// `exclude` — домены, которые пользователь исключил из zapret; к ним добавляются
/// домены VPN-серверов.
pub fn user_lists(
    domains: &[String],
    exclude: &[String],
    server_domains: &[String],
    server_ips: &[std::net::IpAddr],
) -> Result<UserLists, ZapretError> {
    let join = |items: &[String], empty: &str| {
        if items.is_empty() {
            format!("{empty}\n")
        } else {
            items.iter().map(|d| format!("{d}\n")).collect::<String>()
        }
    };
    for d in domains.iter().chain(exclude).chain(server_domains) {
        if !valid_domain(d) {
            return Err(ZapretError::Domain(d.clone()));
        }
    }
    let excluded: Vec<String> = exclude.iter().chain(server_domains).cloned().collect();
    let ips: Vec<String> = server_ips
        .iter()
        .map(|ip| match ip {
            std::net::IpAddr::V4(v4) => format!("{v4}/32"),
            std::net::IpAddr::V6(v6) => format!("{v6}/128"),
        })
        .collect();
    Ok(UserLists {
        general: join(domains, EMPTY_HOSTLIST),
        exclude: join(&excluded, EMPTY_HOSTLIST),
        ipset_exclude: join(&ips, EMPTY_IPSET),
    })
}
