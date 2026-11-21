//! Тесты WFP: часть требует прав администратора (`--ignored`).

use super::*;
use std::net::TcpStream;
use std::time::Duration;

/// Фильтры WFP действуют на весь компьютер: пока один тест держит kill switch,
/// соседний не выйдет в сеть. Тесты с фильтрами идут по одному.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static WFP: std::sync::Mutex<()> = std::sync::Mutex::new(());
    WFP.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn connects(target: &str) -> bool {
    let target = target.parse().unwrap();
    TcpStream::connect_timeout(&target, Duration::from_secs(3)).is_ok()
}

#[test]
fn loopback_interface_has_luid() {
    assert!(interface_luid("Loopback Pseudo-Interface 1").is_some());
    assert!(interface_luid("такого-интерфейса-нет").is_none());
}

/// Без прав администратора WFP отказывает — это должна быть понятная ошибка, а не падение.
#[test]
fn without_admin_rights_returns_error() {
    if crate::win::is_elevated() {
        return;
    }
    let err = KillSwitch::enable(&[], None, false)
        .err()
        .expect("без прав kill switch не включается");
    assert!(err.to_string().contains("WFP"), "{err}");
    let err = DnsGuard::enable(&[], 0, true)
        .err()
        .expect("без прав защита DNS не включается");
    assert!(err.to_string().contains("WFP"), "{err}");
}

/// Только из терминала администратора:
/// `cargo test -p kvt-service kill_switch -- --ignored`
/// Пока kill switch включён, этот процесс (его нет в списке разрешённых) не может
/// выйти в интернет; после выключения — может.
#[test]
#[ignore = "нужны права администратора"]
fn kill_switch_blocks_and_releases() {
    let _serial = serial();
    assert!(
        connects("1.1.1.1:443"),
        "нет интернета — тест не имеет смысла"
    );
    let ks = KillSwitch::enable(&[], None, false).expect("kill switch");
    assert!(!connects("1.1.1.1:443"), "kill switch пропустил соединение");
    drop(ks);
    assert!(
        connects("1.1.1.1:443"),
        "после выключения соединение должно работать"
    );
}

/// Только из терминала администратора:
/// `cargo test -p kvt-service kill_switch -- --ignored`
/// Разрешённая программа от той же учётной записи, что и служба (здесь — этот
/// тест), выходит в сеть: условие `ALE_USER_ID` совпадает со своим SID.
#[test]
#[ignore = "нужны права администратора"]
fn kill_switch_permits_app_of_own_account() {
    let _serial = serial();
    assert!(
        connects("1.1.1.1:443"),
        "нет интернета — тест не имеет смысла"
    );
    let exe = std::env::current_exe().unwrap();
    let ks = KillSwitch::enable(&[&exe], None, false).expect("kill switch");
    assert!(
        connects("1.1.1.1:443"),
        "своя программа той же учётной записи заблокирована"
    );
    drop(ks);
}

/// Только из терминала администратора:
/// `cargo test -p kvt-service kill_switch -- --ignored`
/// Адрес, открытый тестовому ядру, доступен; другие — нет; после закрытия — нет.
#[test]
#[ignore = "нужны права администратора"]
fn kill_switch_probe_opens_only_given_address() {
    let _serial = serial();
    assert!(
        connects("1.1.1.1:443") && connects("8.8.8.8:443"),
        "нет интернета — тест не имеет смысла"
    );
    let exe = std::env::current_exe().unwrap();
    let mut ks = KillSwitch::enable(&[], None, false).expect("kill switch");
    assert!(!connects("1.1.1.1:443"), "kill switch пропустил соединение");
    ks.open_probe(&[&exe], &["1.1.1.1".parse().unwrap()])
        .expect("адрес открыт");
    assert!(connects("1.1.1.1:443"), "открытый адрес недоступен");
    assert!(!connects("8.8.8.8:443"), "открылся не только нужный адрес");
    ks.close_probe();
    assert!(!connects("1.1.1.1:443"), "адрес не закрылся");
    drop(ks);
}

/// Только из терминала администратора:
/// `cargo test -p kvt-service dns_guard -- --ignored`
/// Защита DNS закрывает порты 53 и 853 мимо туннеля, остальное не трогает.
#[test]
#[ignore = "нужны права администратора"]
fn dns_guard_blocks_only_dns() {
    let _serial = serial();
    assert!(
        connects("1.1.1.1:53"),
        "DNS по TCP не отвечает — тест не имеет смысла"
    );
    // Туннеля в тесте нет — вместо него интерфейс, которым ничто не ходит наружу.
    let luid = interface_luid("Loopback Pseudo-Interface 1").expect("loopback");
    let guard = DnsGuard::enable(&[], luid, false).expect("защита DNS");
    assert!(!connects("1.1.1.1:53"), "DNS мимо туннеля прошёл");
    assert!(!connects("1.1.1.1:853"), "DNS-over-TLS мимо туннеля прошёл");
    assert!(connects("1.1.1.1:443"), "защита DNS закрыла не только DNS");
    drop(guard);
    assert!(
        connects("1.1.1.1:53"),
        "после выключения DNS должен работать"
    );
}

/// Только из терминала администратора и при работающем IPv6:
/// `cargo test -p kvt-service dns_guard -- --ignored`
/// TUN без IPv6: IPv6 мимо туннеля закрыт, IPv4 работает.
#[test]
#[ignore = "нужны права администратора"]
fn dns_guard_blocks_ipv6_without_tun_ipv6() {
    let _serial = serial();
    const V6: &str = "[2606:4700:4700::1111]:443";
    if !connects(V6) {
        eprintln!("IPv6 у провайдера нет — проверять нечего");
        return;
    }
    let luid = interface_luid("Loopback Pseudo-Interface 1").expect("loopback");
    let guard = DnsGuard::enable(&[], luid, true).expect("защита DNS");
    assert!(!connects(V6), "IPv6 мимо туннеля прошёл");
    assert!(connects("1.1.1.1:443"), "закрылся и IPv4");
    drop(guard);
    assert!(connects(V6), "после выключения IPv6 должен работать");
}
