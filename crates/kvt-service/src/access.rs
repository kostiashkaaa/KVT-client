//! Кто из пользователей Windows может управлять службой.
//!
//! Pipe открыт всем, кто вошёл в систему интерактивно (`win::PIPE_SDDL`), а клиент
//! проверяется по пути и хешу — но настоящий `kvt.exe` может запустить и второй
//! пользователь того же компьютера. Пока VPN или zapret работает (или kill switch
//! держит интернет закрытым), менять это может только тот, кто их включил, или
//! администратор. Иначе второй пользователь отключил бы чужой VPN и kill switch,
//! открыл бы выход мимо туннеля (`ProbeOpen`) или прочёл журнал сетевых запросов.
//!
//! Владелец помнится в памяти и восстанавливается после перезапуска службы
//! (сбой с kill switch) из отметки на диске: туда при подключении дописывается
//! SID включившего — каталог `run` доступен только SYSTEM и администраторам.

use crate::win::User;
use kvt_core::ipc::{Request, Response, ServiceStatus};
use std::sync::Mutex;

/// SID пользователя, чья команда запустила VPN или zapret.
#[derive(Debug, Default)]
pub struct Owner(Mutex<Option<String>>);

impl Owner {
    /// Владелец, восстановленный после сбоя службы: SID из отметки kill switch.
    pub fn restored(sid: Option<String>) -> Self {
        Self(Mutex::new(sid))
    }

    /// Пускать ли команду `client` при статусе `status`. Запуск от того, кого
    /// пустили, делает его владельцем.
    pub fn admit(&self, client: &User, status: &ServiceStatus, request: &Request) -> bool {
        let Ok(mut owner) = self.0.lock() else {
            return client.admin || harmless(request);
        };
        if !permits(owner.as_deref(), busy(status), client, request) {
            return false;
        }
        if matches!(request, Request::Connect(_) | Request::StartZapret(_)) {
            *owner = Some(client.sid.clone());
        }
        true
    }
}

/// Ответ на команду, которую не пустили.
pub fn refusal() -> Response {
    Response::Error {
        message: kvt_core::i18n::tr(
            "VPN включил другой пользователь Windows. Управлять им может он или администратор.",
            "Another Windows user turned on the VPN. Only they or an administrator can control it.",
        )
        .into(),
    }
}

fn permits(owner: Option<&str>, busy: bool, client: &User, request: &Request) -> bool {
    client.admin || harmless(request) || !busy || owner.is_none_or(|o| o == client.sid)
}

/// VPN или zapret работает, запускается, или kill switch держит интернет закрытым.
fn busy(status: &ServiceStatus) -> bool {
    !matches!(
        status,
        ServiceStatus::Disconnected | ServiceStatus::Failed { blocked: false, .. }
    )
}

/// Можно любому: только чтение, без имён серверов и адресов.
fn harmless(request: &Request) -> bool {
    matches!(
        request,
        Request::Hello { .. }
            | Request::Status
            | Request::ZapretStrategies
            | Request::ZapretInfo
            | Request::ZapretConflicts
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::core_select::CoreKind;

    fn user(sid: &str, admin: bool) -> User {
        User {
            sid: sid.into(),
            admin,
        }
    }

    fn start() -> Request {
        Request::StartZapret(Box::new(
            serde_json::from_str(r#"{"strategy":"general"}"#).unwrap(),
        ))
    }

    fn connected() -> ServiceStatus {
        ServiceStatus::Connected {
            core: CoreKind::Xray,
        }
    }

    #[test]
    fn other_user_cannot_touch_running_vpn() {
        let owner = Owner::default();
        let (alice, bob) = (user("S-1-5-21-1", false), user("S-1-5-21-2", false));
        let idle = ServiceStatus::Disconnected;
        assert!(owner.admit(&alice, &idle, &Request::Disconnect));
        // Запуск делает владельцем того, кто его начал.
        assert!(owner.admit(&alice, &idle, &start()));
        for request in [
            Request::Disconnect,
            Request::NetLog,
            Request::ProbeOpen { ips: vec![] },
            Request::ProbeClose,
            Request::ServiceLog,
            Request::ZapretRepair,
        ] {
            assert!(!owner.admit(&bob, &connected(), &request), "{request:?}");
            assert!(owner.admit(&alice, &connected(), &request), "{request:?}");
        }
        assert!(owner.admit(&bob, &connected(), &Request::Status));
        assert!(owner.admit(&bob, &connected(), &Request::ZapretInfo));
    }

    #[test]
    fn admin_and_idle_service_let_anyone_in() {
        let owner = Owner::default();
        let (alice, bob) = (user("S-1-5-21-1", false), user("S-1-5-21-2", false));
        assert!(owner.admit(&alice, &ServiceStatus::Disconnected, &start()));
        assert!(owner.admit(
            &user("S-1-5-21-3", true),
            &connected(),
            &Request::Disconnect
        ));
        let failed = ServiceStatus::Failed {
            reason: String::new(),
            blocked: false,
        };
        assert!(owner.admit(&bob, &failed, &Request::Disconnect));
        assert!(owner.admit(&bob, &failed, &start()));
        // Теперь владелец — bob.
        assert!(!owner.admit(&alice, &connected(), &Request::Disconnect));
    }

    #[test]
    fn kill_switch_holding_internet_counts_as_running() {
        let owner = Owner::default();
        let blocked = ServiceStatus::Failed {
            reason: String::new(),
            blocked: true,
        };
        let (alice, bob) = (user("S-1-5-21-1", false), user("S-1-5-21-2", false));
        assert!(owner.admit(&alice, &ServiceStatus::Disconnected, &start()));
        assert!(!owner.admit(&bob, &blocked, &Request::Disconnect));
        // Служба перезапустилась после сбоя: владельца нет.
        assert!(Owner::default().admit(&bob, &blocked, &Request::Disconnect));
    }

    /// После перезапуска службы (сбой с kill switch) владельцем остаётся тот, кто
    /// его включил: SID восстановлен из отметки kill switch (С-2 аудита).
    #[test]
    fn restored_owner_keeps_guarding_after_service_restart() {
        let blocked = ServiceStatus::Failed {
            reason: String::new(),
            blocked: true,
        };
        let (alice, bob) = (user("S-1-5-21-1", false), user("S-1-5-21-2", false));
        let owner = Owner::restored(Some(alice.sid.clone()));
        assert!(!owner.admit(&bob, &blocked, &Request::Disconnect));
        assert!(owner.admit(&alice, &blocked, &Request::Disconnect));
        // И новую сессию тоже может начать только он.
        assert!(!owner.admit(&bob, &blocked, &start()));
        assert!(owner.admit(&alice, &blocked, &start()));
    }
}
