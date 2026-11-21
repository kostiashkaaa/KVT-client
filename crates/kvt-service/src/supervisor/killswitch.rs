//! Kill switch и DNS только через туннель (фильтры WFP), отметка kill switch на
//! случай падения службы и временный выход тестовому ядру окна (`open_probe`).

use super::*;

/// Сколько живут адреса, открытые тестовому ядру: проверка укладывается в 5 минут.
pub(super) const PROBE_TTL: Duration = Duration::from_secs(10 * 60);

/// Отметка «kill switch включён» в каталоге `run` (см. `mark_kill_switch`).
pub(super) const KILL_SWITCH_MARKER: &str = "kill-switch.on";

pub(super) fn clear_marker(marker: &Path) {
    match std::fs::remove_file(marker) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "отметка kill switch не стёрта"),
    }
}

impl Supervisor {
    /// Ядра и служба. Оба ядра: тестовое ядро проверки серверов бывает не тем,
    /// что подключено.
    pub(super) fn trusted_apps(&self) -> Result<Vec<PathBuf>, ConnectError> {
        let service = std::env::current_exe().map_err(ConnectError::wfp)?;
        Ok(vec![
            CoreSpec::new(CoreKind::Xray, &self.paths).exe,
            CoreSpec::new(CoreKind::SingBox, &self.paths).exe,
            service,
        ])
    }

    /// `block_ipv6` — TUN поднят без IPv6: IPv6 мимо туннеля тоже закрывается.
    pub(super) fn enable_dns_guard(
        &mut self,
        luid: u64,
        block_ipv6: bool,
    ) -> Result<(), ConnectError> {
        let apps = self.trusted_apps()?;
        let apps: Vec<&Path> = apps.iter().map(PathBuf::as_path).collect();
        let guard = DnsGuard::enable(&apps, luid, block_ipv6).map_err(ConnectError::wfp)?;
        if block_ipv6 {
            tracing::info!("TUN без IPv6: IPv6 мимо туннеля закрыт");
        }
        if let Some(running) = self.running.as_mut() {
            running.dns_guard = Some(guard);
        }
        Ok(())
    }

    /// Kill switch пропускает оба ядра, а не только подключённое: «Проверить» при VPN
    /// запускает тестовое ядро того типа, который нужен серверу, и без этого сервер на
    /// другом ядре выглядел бы мёртвым. Оба файла лежат рядом со службой.
    /// `tun_luid` — интерфейс туннеля: трафик приложений через него разрешён. `None` —
    /// переходная версия до подъёма туннеля; полная встанет на её место, подслои у
    /// сессий разные — без щели.
    pub(super) fn enable_kill_switch(&mut self, tun_luid: Option<u64>) -> Result<(), ConnectError> {
        let apps = self.trusted_apps()?;
        let apps: Vec<&Path> = apps.iter().map(PathBuf::as_path).collect();
        // «Гибрид»: пакеты, которые winws отправляет заново, Windows приписывает ядру
        // системы — kill switch должен их пропускать (см. `wfp::KillSwitch::enable`).
        let hybrid = self.zapret.is_some();
        let ks = KillSwitch::enable(&apps, tun_luid, hybrid).map_err(ConnectError::wfp)?;
        if tun_luid.is_some() {
            tracing::info!("kill switch включён");
        } else {
            tracing::info!(
                "kill switch включён до запуска ядра — интернет закрыт, пока поднимается туннель"
            );
        }
        self.kill_switch = Some(ks);
        self.mark_kill_switch(true);
        Ok(())
    }

    /// Отметка на диске «kill switch включён»: фильтры WFP динамические и пропадают
    /// вместе с процессом службы, а отметка переживает падение — по ней служба после
    /// перезапуска снова закрывает интернет (`restore_kill_switch`).
    pub(super) fn mark_kill_switch(&self, on: bool) {
        let marker = self.paths.run.join(KILL_SWITCH_MARKER);
        let result = if on {
            std::fs::write(&marker, b"")
        } else {
            match std::fs::remove_file(&marker) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                other => other,
            }
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, on, "отметка kill switch не записана");
        }
    }

    /// Служба запустилась, а отметка kill switch осталась: прошлый процесс упал с
    /// включённым kill switch. Интернет снова закрывается до решения окна
    /// («Подключить» или «Отключить»). Отметка с прошлой загрузки Windows (выключили
    /// питание) не действует: после перезагрузки закрытого интернета никто не ждёт.
    /// Владелец отметки (SID включившего kill switch) возвращается в `Owner`:
    /// закрытым интернетом управляет он или администратор, не любой пользователь.
    pub fn restore_kill_switch(&mut self) -> bool {
        // Каталог только для SYSTEM и администраторов: чужой каталог `private_dir`
        // убирает в сторону вместе с отметкой.
        if secure_dir(&self.paths.run).is_err() {
            return false;
        }
        let marker = self.paths.run.join(KILL_SWITCH_MARKER);
        let Ok(written) = std::fs::metadata(&marker).and_then(|m| m.modified()) else {
            return false;
        };
        if crate::win::boot_time().is_none_or(|boot| written < boot) {
            tracing::info!("отметка kill switch с прошлой загрузки Windows — не восстанавливаем");
            self.mark_kill_switch(false);
            return false;
        }
        let sid = std::fs::read_to_string(&marker).unwrap_or_default();
        let sid = sid.trim();
        self.restored_owner = (!sid.is_empty()).then(|| sid.to_owned());
        let enabled = self.trusted_apps().and_then(|apps| {
            let apps: Vec<&Path> = apps.iter().map(PathBuf::as_path).collect();
            KillSwitch::enable(&apps, None, false).map_err(ConnectError::wfp)
        });
        match enabled {
            Ok(ks) => {
                tracing::warn!("служба перезапустилась после сбоя: kill switch восстановлен");
                self.kill_switch = Some(ks);
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "kill switch после сбоя не восстановлен");
                false
            }
        }
    }

    pub fn kill_switch_active(&self) -> bool {
        self.kill_switch.is_some()
    }

    /// Полная проверка серверов из окна при kill switch: тестовому ядру (оно работает
    /// от пользователя) открывается выход мимо туннеля к `ips`. Служебные адреса
    /// (0.0.0.0, multicast), loopback и частные сети не открываются: kill switch их
    /// и так пропускает, а VPN-сервер в частных сетях не живёт. Без kill switch
    /// открывать нечего.
    pub fn open_probe(&mut self, ips: &[std::net::IpAddr]) -> Result<(), ConnectError> {
        let Some(ks) = self.kill_switch.as_mut() else {
            return Ok(());
        };
        let ips: Vec<std::net::IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| global_address(*ip))
            .collect();
        if ks.probe_len() + ips.len() > kvt_core::ipc::MAX_PROBE_ADDRS {
            return Err(ConnectError::TooManyProbeAddresses);
        }
        let cores = [
            CoreSpec::new(CoreKind::Xray, &self.paths).exe,
            CoreSpec::new(CoreKind::SingBox, &self.paths).exe,
        ];
        let cores: Vec<&Path> = cores.iter().map(PathBuf::as_path).collect();
        ks.open_probe(&cores, &ips).map_err(ConnectError::wfp)?;
        self.probe_until = Some(Instant::now() + PROBE_TTL);
        tracing::info!(
            addresses = ks.probe_len(),
            "тестовому ядру открыты адреса серверов"
        );
        Ok(())
    }

    /// Закрывает адреса, открытые тестовому ядру.
    pub fn close_probe(&mut self) {
        self.probe_until = None;
        if let Some(ks) = self.kill_switch.as_mut() {
            if ks.probe_len() > 0 {
                ks.close_probe();
                tracing::info!("адреса тестового ядра закрыты");
            }
        }
    }

    /// Закрывает адреса тестового ядра, если окно не закрыло их само вовремя.
    pub fn expire_probe(&mut self) {
        if self
            .probe_until
            .is_some_and(|until| Instant::now() >= until)
        {
            tracing::warn!("проверка серверов не закрыла адреса — закрыты по времени");
            self.close_probe();
        }
    }
}

/// Адрес из публичных сетей: частные (`is_private`), link-local, unique local и
/// служебные (0.0.0.0, multicast, broadcast) тестовому ядру не открываются —
/// kill switch пропускает их сам, а VPN-сервер в частных сетях не живёт.
fn global_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_private()
                && !v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unicast_link_local()
                && !v6.is_unique_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::global_address;

    #[test]
    fn only_public_addresses_are_opened_to_the_probe() {
        let ok = [
            "203.0.113.7",
            "198.51.100.2",
            "2001:db8::1",
            "2a00:1450:4002:41a::71",
        ];
        let refused = [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "10.0.0.5",
            "172.16.1.2",
            "192.168.1.2",
            "169.254.7.7",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
        ];
        for ip in ok {
            assert!(
                global_address(ip.parse().expect("адрес")),
                "{ip} должен открываться"
            );
        }
        for ip in refused {
            assert!(
                !global_address(ip.parse().expect("адрес")),
                "{ip} не должен открываться"
            );
        }
    }
}
