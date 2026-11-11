//! Полная проверка сервера через тестовое ядро.
//!
//! Для каждого сервера на несколько секунд запускается Xray или sing-box без TUN
//! и без прав администратора, с одним SOCKS5-входом на 127.0.0.1 (случайный порт,
//! случайный логин и пароль). Через него одним соединением скачивается ~200 КБ:
//! к VPN-серверу уходит ровно одно TLS-рукопожатие, а по потоку видно и задержку,
//! и заморозку после первых килобайт.
//!
//! Если VPN подключён, тестовое ядро и TCP-пинг уходят с адреса физического
//! адаптера (`netinfo::physical_ipv4`) — мимо TUN, как без VPN. Kill switch их
//! пропускает: фильтр разрешает исполняемый файл ядра, а тестовое ядро — тот же
//! файл из каталога программы.

use crate::{query_status, AppState};
use kvt_core::compile::{compile_probe, ProbeInbound};
use kvt_core::core_select::{select_core, CoreKind};
use kvt_core::ipc::ServiceStatus;
use kvt_core::probe::ProbeObservation;
use kvt_core::tester::{self, tcp_ping_from, Outcome, Prober, QuickResult};
use kvt_core::Server;
use serde::Serialize;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};

/// Файл со скоростного теста Cloudflare. Обычный HTTP: запрос идёт внутри туннеля
/// (снаружи видно только шифрованное соединение с VPN-сервером), а лишний TLS
/// исказил бы задержку несколькими круговыми задержками.
const TEST_URL: &str = "http://speed.cloudflare.com/__down?bytes=204800";
const TARGET_BYTES: u64 = 200 * 1024;
/// Сколько ждём первого ответа: дольше — похоже на заморозку рукопожатия.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(12);
/// Пауза в потоке, после которой считаем, что его заморозили.
const STALL: Duration = Duration::from_secs(6);
/// Отказ быстрее этого — сервер отклонил подключение, а не ТСПУ молчит.
const FAST_FAILURE: Duration = Duration::from_secs(3);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Бюджет всей проверки: что не успели — «повторить позже».
const BUDGET: Duration = Duration::from_secs(5 * 60);

pub const RESULT_EVENT: &str = "probe-result";

pub struct CoreProber {
    cores: PathBuf,
    work: PathBuf,
    /// Адрес физического адаптера при подключённом VPN.
    source: Option<std::net::Ipv4Addr>,
}

fn random_token() -> String {
    let mut h = RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    format!("{:016x}", h.finish())
}

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

async fn wait_for_port(port: u16, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Итог загрузки через туннель.
struct Measured {
    responded: bool,
    rejected: bool,
    latency: Option<Duration>,
    bytes: u64,
    stalled: bool,
}

async fn download_via_socks(port: u16, user: &str, password: &str) -> Measured {
    let mut m = Measured {
        responded: false,
        rejected: false,
        latency: None,
        bytes: 0,
        stalled: false,
    };
    let Ok(proxy) = reqwest::Proxy::all(format!("socks5h://{user}:{password}@127.0.0.1:{port}"))
    else {
        return m;
    };
    let Ok(client) = reqwest::Client::builder().proxy(proxy).build() else {
        return m;
    };
    let start = Instant::now();
    let response = match tokio::time::timeout(RESPONSE_TIMEOUT, client.get(TEST_URL).send()).await {
        Ok(Ok(r)) if r.status().is_success() => r,
        Ok(_) => {
            // Ошибка пришла сама: быстрый отказ — сервер отклонил, медленный — сеть.
            m.rejected = start.elapsed() < FAST_FAILURE;
            return m;
        }
        Err(_) => return m,
    };
    m.responded = true;
    m.latency = Some(start.elapsed());
    let mut response = response;
    loop {
        match tokio::time::timeout(STALL, response.chunk()).await {
            Ok(Ok(Some(chunk))) => m.bytes += chunk.len() as u64,
            Ok(_) => break,
            Err(_) => {
                m.stalled = true;
                break;
            }
        }
        if m.bytes >= TARGET_BYTES {
            break;
        }
    }
    m
}

impl CoreProber {
    async fn run_core(&self, server: &Server) -> Result<Measured, ()> {
        let core = select_core(server).core;
        let port = free_port().map_err(|_| ())?;
        let (user, password) = (random_token(), random_token());
        let config = compile_probe(
            core,
            server,
            &ProbeInbound {
                port,
                user: &user,
                password: &password,
                source: self.source,
            },
        )
        .map_err(|_| ())?;
        let path = self.work.join(format!("probe-{port}.json"));
        std::fs::write(&path, serde_json::to_vec(&config).map_err(|_| ())?).map_err(|_| ())?;

        let mut cmd = match core {
            CoreKind::Xray => {
                let mut c = tokio::process::Command::new(self.cores.join("xray.exe"));
                c.args(["run", "-c"]).arg(&path);
                c
            }
            CoreKind::SingBox => {
                let mut c = tokio::process::Command::new(self.cores.join("sing-box.exe"));
                c.args(["run", "-c"]).arg(&path).arg("-D").arg(&self.work);
                c
            }
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .kill_on_drop(true);
        let spawned = cmd.spawn();
        let ready = match &spawned {
            Ok(_) => wait_for_port(port, Duration::from_secs(5)).await,
            Err(_) => false,
        };
        // В конфиге ключ сервера — на диске он не задерживается.
        let _ = std::fs::remove_file(&path);
        let mut child = spawned.map_err(|_| ())?;
        if !ready {
            let _ = child.kill().await;
            return Err(());
        }
        let measured = download_via_socks(port, &user, &password).await;
        let _ = child.kill().await;
        Ok(measured)
    }
}

impl Prober for CoreProber {
    async fn probe(&self, server: Server) -> ProbeObservation {
        let mut obs = ProbeObservation {
            dns_resolved: true,
            ..Default::default()
        };
        // Сначала дешёвая проверка TCP (без TLS); Hysteria2 работает по UDP — её не проверить так.
        if !server.protocol.is_quic() {
            match tcp_ping_from(
                &server.address,
                server.port,
                self.source,
                Duration::from_secs(4),
            )
            .await
            {
                QuickResult::DnsFailed => {
                    obs.dns_resolved = false;
                    return obs;
                }
                QuickResult::Unreachable => return obs,
                _ => {}
            }
        }
        obs.tcp_connected = true;
        match self.run_core(&server).await {
            Err(()) => obs.core_error = true,
            Ok(m) => {
                obs.tls_handshake_done = m.responded;
                obs.rejected = m.rejected;
                obs.latency = m.latency;
                obs.bytes_received = m.bytes;
                obs.stalled = m.stalled;
                obs.download_completed = m.bytes >= TARGET_BYTES;
            }
        }
        obs
    }
}

#[derive(Clone, Serialize)]
struct ProbeEvent {
    key: String,
    outcome: Outcome,
}

impl CoreProber {
    /// Тестовые ядра из каталога программы, рабочие файлы — во временном каталоге.
    /// `source` — адрес физического адаптера, если VPN подключён.
    pub(crate) fn new(source: Option<std::net::Ipv4Addr>) -> Result<Self, String> {
        let work = std::env::temp_dir().join("kvt-probe");
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        Ok(Self {
            cores: cores_dir()?,
            work,
            source,
        })
    }
}

fn cores_dir() -> Result<PathBuf, String> {
    let dir = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .map(|p| p.join("cores"))
        .ok_or(kvt_core::i18n::tr(
            "не найден каталог программы",
            "the app folder wasn't found",
        ))?;
    if !dir.join("xray.exe").exists() || !dir.join("sing-box.exe").exists() {
        return Err(kvt_core::i18n::tr(
            "Не найдены ядра Xray и sing-box. Для разработки: scripts\\fetch-cores.ps1",
            "The Xray and sing-box cores weren't found. For development: scripts\\fetch-cores.ps1",
        )
        .into());
    }
    Ok(dir)
}

/// Полная проверка серверов одной подписки (`group`) или всех. Результаты
/// приходят в интерфейс событием `probe-result` по мере готовности.
#[tauri::command]
pub async fn full_check(
    group: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // VPN подключён — проверка уходит с физического адаптера мимо туннеля.
    let source = if matches!(
        query_status().await,
        Ok(Some(
            ServiceStatus::Connected { .. } | ServiceStatus::Connecting
        ))
    ) {
        let found = tauri::async_runtime::spawn_blocking(crate::netinfo::physical_ipv4)
            .await
            .ok()
            .flatten();
        Some(found.ok_or(kvt_core::i18n::tr(
            "Не нашёлся сетевой адаптер, через который можно проверить серверы мимо VPN. Отключите VPN и проверьте снова.",
            "Couldn't find a network adapter to check servers past the VPN. Disconnect the VPN and check again.",
        ))?)
    } else {
        None
    };
    if state.checking.swap(true, Ordering::SeqCst) {
        return Err(kvt_core::i18n::tr("Проверка уже идёт", "A check is already running").into());
    }
    let result = async {
        let (keys, servers) = crate::servers_of(&state, group.as_deref())?;
        let prober = Arc::new(CoreProber::new(source)?);
        // Состояние NetGovernor (лимиты и заморозки по SNI) общее для всего приложения.
        let mut governor =
            std::mem::take(&mut *state.governor.lock().map_err(crate::errors::state)?);
        let events = app.clone();
        let event_keys = keys.clone();
        let outcomes = tester::full_check(
            &servers,
            prober,
            &mut governor,
            BUDGET,
            move |index, outcome| {
                let _ = events.emit(
                    RESULT_EVENT,
                    ProbeEvent {
                        key: event_keys[index].clone(),
                        outcome: outcome.clone(),
                    },
                );
            },
        )
        .await;
        *state.governor.lock().map_err(crate::errors::state)? = governor;
        // Результаты нужны и автопереключению: оно выбирает замену среди проверенных
        // (и после перезапуска KVT).
        crate::outcomes::record(&state, keys.into_iter().zip(outcomes));
        Ok::<_, String>(())
    }
    .await;
    state.checking.store(false, Ordering::SeqCst);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use kvt_core::model::{Security, Transport};
    use kvt_core::probe::{classify, Verdict};
    use kvt_core::Secret;

    fn dev_cores() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/cores")
    }

    fn ss_server(port: u16) -> Server {
        Server {
            name: "local".into(),
            address: "127.0.0.1".into(),
            port,
            protocol: kvt_core::model::Protocol::Shadowsocks {
                method: "aes-128-gcm".into(),
                password: Secret::new("kvt-test"),
            },
            transport: Transport::Tcp,
            security: Security::None,
            fragment: None,
            mux: None,
        }
    }

    /// Вся цепочка на настоящих ядрах: локальный сервер Shadowsocks (sing-box)
    /// → тестовое ядро с SOCKS5 → загрузка 200 КБ с Cloudflare.
    /// `cargo test -p kvt-app real_probe -- --ignored --nocapture` (нужны ядра и интернет).
    #[tokio::test]
    #[ignore = "нужны ядра (scripts/fetch-cores.ps1) и интернет"]
    async fn real_probe_through_local_server() {
        let cores = dev_cores();
        let work = std::env::temp_dir().join("kvt-probe-test");
        std::fs::create_dir_all(&work).unwrap();

        let port = free_port().unwrap();
        let server_cfg = serde_json::json!({
            "log": { "level": "warn" },
            "inbounds": [{ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
                           "method": "aes-128-gcm", "password": "kvt-test" }],
            "outbounds": [{ "type": "direct" }]
        });
        let cfg_path = work.join("server.json");
        std::fs::write(&cfg_path, serde_json::to_vec(&server_cfg).unwrap()).unwrap();
        let mut server = tokio::process::Command::new(cores.join("sing-box.exe"))
            .args(["run", "-c"])
            .arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        assert!(
            wait_for_port(port, Duration::from_secs(5)).await,
            "тестовый сервер не запустился"
        );

        let prober = CoreProber {
            cores,
            work,
            source: None,
        };
        let obs = prober.probe(ss_server(port)).await;
        println!("{obs:?} → {:?}", classify(&obs));
        assert_eq!(classify(&obs), Verdict::Works);
        assert!(obs.bytes_received >= TARGET_BYTES);

        // Сервер выключен — сервер недоступен, а не «заморозка».
        server.kill().await.unwrap();
        let obs = prober.probe(ss_server(port)).await;
        assert_eq!(classify(&obs), Verdict::Unreachable);
    }

    #[test]
    fn tokens_are_distinct() {
        assert_ne!(random_token(), random_token());
        assert_eq!(random_token().len(), 16);
    }
}
