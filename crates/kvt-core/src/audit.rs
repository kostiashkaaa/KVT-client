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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Скрипт сбора фактов. Ничего не меняет; вывод — одна строка JSON ([`Facts`]).
/// Значения берутся из реестра, CIM и командлетов, а не из текста, поэтому от
/// языка Windows не зависят.
pub const SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$m = 'winws|goodbyedpi|zapret|discordfix'
$r = [ordered]@{}

$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$r.proxy = @{ enable = [int]$is.ProxyEnable; server = [string]$is.ProxyServer; autoConfigUrl = [string]$is.AutoConfigURL }
$wh = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections').WinHttpSettings
$r.winhttp = if ($wh) { [Convert]::ToBase64String([byte[]]$wh) } else { '' }
$tc = Get-NetTeredoConfiguration
$ts = Get-NetTeredoState
$r.teredo = @{ type = [string]$tc.Type; state = [string]$ts.State }

$r.adapters = @(Get-NetAdapter | ForEach-Object {
  $ns = (Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $_.InterfaceGuid)).NameServer
  @{ name = [string]$_.Name; description = [string]$_.InterfaceDescription; status = [string]$_.Status; staticDns = [string]$ns }
})
$r.processes = @(Get-Process | ForEach-Object { @{ pid = [int]$_.Id; name = [string]$_.ProcessName; path = [string]$_.Path } })
$r.antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [string]$_.displayName })
$r.services = @(Get-CimInstance Win32_Service | Where-Object { ($_.Name + ' ' + $_.DisplayName + ' ' + $_.PathName) -match $m } | ForEach-Object {
  @{ name = [string]$_.Name; displayName = [string]$_.DisplayName; state = [string]$_.State; startMode = [string]$_.StartMode; path = [string]$_.PathName }
})

function Disabled($key, $name) {
  $v = (Get-ItemProperty -LiteralPath $key -Name $name).$name
  if ($v -and $v.Length -gt 0) { return (($v[0] -band 1) -eq 1) }
  return $false
}
$ap = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\'
$auto = @()
foreach ($loc in @(
  @('hkcu_run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', ('HKCU:\' + $ap + 'Run')),
  @('hklm_run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', ('HKLM:\' + $ap + 'Run')))) {
  $k = Get-Item -LiteralPath $loc[1]
  if ($k) {
    foreach ($n in $k.GetValueNames()) {
      if ($n) { $auto += @{ location = $loc[0]; name = [string]$n; command = [string]$k.GetValue($n); disabled = (Disabled $loc[2] $n) } }
    }
  }
}
$sh = New-Object -ComObject WScript.Shell
foreach ($loc in @(
  @('hkcu_startup', [Environment]::GetFolderPath('Startup'), ('HKCU:\' + $ap + 'StartupFolder')),
  @('common_startup', [Environment]::GetFolderPath('CommonStartup'), ('HKLM:\' + $ap + 'StartupFolder')))) {
  if (-not $loc[1]) { continue }
  Get-ChildItem -LiteralPath $loc[1] -File | ForEach-Object {
    $cmd = $_.FullName
    if ($_.Extension -eq '.lnk') {
      $l = $sh.CreateShortcut($_.FullName)
      $cmd = ($l.TargetPath + ' ' + $l.Arguments).Trim()
    } elseif ($_.Extension -match '^\.(bat|cmd)$') {
      $text = [IO.File]::ReadAllText($_.FullName)
      $cmd = $_.FullName + ' ' + $text.Substring(0, [Math]::Min(4000, $text.Length))
    }
    $auto += @{ location = $loc[0]; name = [string]$_.Name; command = [string]$cmd; disabled = (Disabled $loc[2] $_.Name) }
  }
}
Get-ScheduledTask | ForEach-Object {
  $t = $_
  $a = (@($t.Actions) | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) -join '; '
  if (($t.TaskName + ' ' + $a) -match $m) {
    $auto += @{ location = 'task'; name = ([string]$t.TaskPath + [string]$t.TaskName); command = [string]$a; disabled = ([string]$t.State -eq 'Disabled') }
  }
}
$r.autostart = $auto

$b = @()
foreach ($p in @(@('chrome', 'Google\Chrome'), @('edge', 'Microsoft\Edge'), @('yandex', 'Yandex\YandexBrowser'), @('brave', 'BraveSoftware\Brave-Browser'))) {
  $f = Join-Path $env:LOCALAPPDATA ($p[1] + '\User Data\Local State')
  if (Test-Path -LiteralPath $f) {
    $d = (Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json).dns_over_https
    $b += @{ browser = $p[0]; mode = [string]$d.mode; templates = [string]$d.templates }
  }
}
Get-ChildItem -LiteralPath (Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles') -Directory | ForEach-Object {
  $f = Join-Path $_.FullName 'prefs.js'
  if (Test-Path -LiteralPath $f) {
    $text = [IO.File]::ReadAllText($f)
    $mode = if ($text -match 'user_pref\("network\.trr\.mode",\s*(\d+)\)') { $Matches[1] } else { '' }
    $uri = if ($text -match 'user_pref\("network\.trr\.uri",\s*"([^"]*)"\)') { $Matches[1] } else { '' }
    $b += @{ browser = 'firefox'; mode = [string]$mode; templates = [string]$uri }
  }
}
$r.browsers = $b

$r | ConvertTo-Json -Depth 4 -Compress
"#;

/// Аргументы `powershell.exe` для запуска [`SCRIPT`]: скрипт передаётся как
/// `-EncodedCommand` (UTF-16LE в Base64), без временных файлов и экранирования.
pub fn powershell_args() -> Vec<String> {
    use base64::Engine as _;
    let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
    [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .chain([base64::engine::general_purpose::STANDARD.encode(utf16)])
    .collect()
}

// ── Факты ──

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Facts {
    pub proxy: SystemProxy,
    /// Значение `WinHttpSettings` в Base64 (пусто — не задано).
    pub winhttp: String,
    pub teredo: Teredo,
    pub adapters: Vec<Adapter>,
    pub processes: Vec<Process>,
    pub antivirus: Vec<String>,
    pub services: Vec<Service>,
    pub autostart: Vec<Autostart>,
    pub browsers: Vec<BrowserDns>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SystemProxy {
    pub enable: i64,
    pub server: String,
    pub auto_config_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Teredo {
    #[serde(rename = "type")]
    pub kind: String,
    pub state: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Adapter {
    pub name: String,
    pub description: String,
    pub status: String,
    /// DNS, прописанный вручную (через запятую или пробел); пусто — от DHCP.
    pub static_dns: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Process {
    pub pid: u32,
    /// Имя без `.exe`, как его отдаёт `Get-Process`.
    pub name: String,
    /// Пусто, если путь недоступен (процесс другого пользователя или с правами администратора).
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Service {
    pub name: String,
    pub display_name: String,
    /// `Running`, `Stopped`…
    pub state: String,
    /// `Auto`, `Manual`, `Disabled`.
    pub start_mode: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    HkcuRun,
    HklmRun,
    HkcuStartup,
    CommonStartup,
    Task,
}

impl Location {
    /// Отключить может только служба (раздел HKLM, общая папка, задания планировщика).
    pub fn machine_wide(self) -> bool {
        !matches!(self, Location::HkcuRun | Location::HkcuStartup)
    }

    fn title(self) -> &'static str {
        match self {
            Location::HkcuRun | Location::HklmRun => "автозагрузка",
            Location::HkcuStartup | Location::CommonStartup => "папка автозагрузки",
            Location::Task => "планировщик заданий",
        }
    }
}

/// Значение `StartupApproved`, которое пишет «Диспетчер задач» при «Отключить»:
/// первый байт 03, остальное — время (необязательно).
pub const STARTUP_DISABLED: &str = "030000000000000000000000";

impl Location {
    /// Раздел `StartupApproved` для `reg.exe`; у заданий планировщика его нет.
    pub fn approved_key(self) -> Option<&'static str> {
        match self {
            Location::HkcuRun => {
                Some(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
            }
            Location::HklmRun => {
                Some(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
            }
            Location::HkcuStartup => Some(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
            ),
            Location::CommonStartup => Some(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
            ),
            Location::Task => None,
        }
    }
}

/// Найти в свежем сборе фактов запись автозагрузки zapret по идентификатору.
pub fn zapret_autostart_by_id<'a>(
    facts: &'a Facts,
    id: &str,
    own: &OwnDirs,
) -> Option<&'a Autostart> {
    facts
        .autostart
        .iter()
        .find(|a| a.id() == id && is_zapret_autostart(a, own))
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Autostart {
    pub location: Location,
    pub name: String,
    #[serde(default)]
    pub command: String,
    /// Уже отключено (в «Диспетчере задач» или планировщике).
    #[serde(default)]
    pub disabled: bool,
}

impl Autostart {
    /// Постоянный идентификатор записи: по нему служба находит запись сама.
    pub fn id(&self) -> String {
        let mut h = Sha256::new();
        h.update(format!(
            "{:?}\0{}\0{}",
            self.location, self.name, self.command
        ));
        h.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct BrowserDns {
    /// `chrome`, `edge`, `yandex`, `brave`, `firefox`.
    pub browser: String,
    /// Chromium: `off` / `automatic` / `secure`; Firefox: число `network.trr.mode`.
    pub mode: String,
    pub templates: String,
}

pub fn parse_facts(json: &str) -> Result<Facts, String> {
    serde_json::from_str(json.trim().trim_start_matches('\u{feff}'))
        .map_err(|e| format!("не удалось разобрать сведения о системе: {e}"))
}

/// Адрес прокси из `WinHttpSettings` (структура WINHTTP_PROXY_INFO в реестре):
/// 4 байта версии, 4 — счётчика, 4 — флагов (бит 2 — задан прокси), 4 — длины, строка.
pub fn winhttp_proxy(base64_value: &str) -> Option<String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(base64_value.trim())
        .ok()?;
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?))
    };
    if u32_at(8)? & 0x2 == 0 {
        return None;
    }
    let len = u32_at(12)? as usize;
    let proxy = raw.get(16..16 + len)?;
    let proxy = String::from_utf8_lossy(proxy).trim().to_owned();
    (!proxy.is_empty()).then_some(proxy)
}

// ── Находки ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Утечки мимо VPN.
    Leaks,
    /// Программы, которые мешают VPN.
    Conflicts,
    /// Остатки других сборок zapret.
    Zapret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Ok,
    Info,
    Warning,
}

/// Исправление, которое выполняется по кнопке.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fix {
    /// Выключить системный прокси Windows (настройка пользователя).
    DisableSystemProxy,
    /// Закрыть программу пользователя.
    CloseProcess { pid: u32, name: String },
    /// Остановить чужие winws/GoodbyeDPI (`Request::StopConflicts`).
    StopZapret,
    /// Действие службы.
    Service(ServiceFix),
    /// Отключить запись автозагрузки пользователя (как «Отключить» в «Диспетчере задач»).
    DisableUserAutostart { id: String },
}

/// Исправления с правами администратора. Служба не верит параметрам на слово:
/// имя службы и запись автозагрузки должны найтись в её собственном сборе фактов
/// и подходить под признаки zapret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ServiceFix {
    /// `netsh winhttp reset proxy`.
    ResetWinHttpProxy,
    /// `netsh interface teredo set state disabled`.
    DisableTeredo,
    /// Остановить чужую службу zapret и перевести её в ручной запуск (не удаляя).
    DisableZapretService { name: String },
    /// Отключить запись автозагрузки для всех пользователей или задание планировщика.
    DisableAutostart { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub group: Group,
    pub level: Level,
    pub title: String,
    pub detail: String,
    pub fix: Option<Fix>,
}

impl Finding {
    fn new(
        group: Group,
        level: Level,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            group,
            level,
            title: title.into(),
            detail: detail.into(),
            fix: None,
        }
    }

    fn fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }
}

/// Другие VPN-клиенты: имя процесса (без `.exe`, в нижнем регистре) → название.
const VPN_CLIENTS: &[(&str, &str)] = &[
    ("v2rayn", "v2rayN"),
    ("nekoray", "NekoRay"),
    ("nekobox", "NekoBox"),
    ("throne", "Throne"),
    ("hiddify", "Hiddify"),
    ("hiddifycli", "Hiddify"),
    ("happ", "Happ"),
    ("clash-verge", "Clash Verge"),
    ("verge-mihomo", "Clash Verge"),
    ("flclash", "FlClash"),
    ("clash for windows", "Clash for Windows"),
    ("amneziavpn", "AmneziaVPN"),
    ("amneziawg", "AmneziaWG"),
    ("wireguard", "WireGuard"),
    ("openvpn", "OpenVPN"),
    ("openvpn-gui", "OpenVPN"),
    ("outline", "Outline"),
    ("protonvpn", "Proton VPN"),
    ("protonvpn.client", "Proton VPN"),
    ("nordvpn", "NordVPN"),
    ("windscribe", "Windscribe"),
    ("psiphon3", "Psiphon"),
    ("lantern", "Lantern"),
    ("adguardvpn", "AdGuard VPN"),
    ("zapretkvn", "Zapret KVN"),
    ("zapretvpn", "ZapretVPN"),
    ("antizapret", "AntiZapret"),
];

/// Ядра, которые запускают другие клиенты. Считаются чужими, только если путь
/// известен и лежит не в каталоге KVT (свои ядра запускает служба).
const CORES: &[&str] = &["xray", "sing-box", "mihomo", "clash", "tun2socks"];

/// Признаки виртуальных адаптеров других VPN (в описании адаптера).
const TUNNEL_ADAPTERS: &[&str] = &[
    "tap-windows",
    "tap-protonvpn",
    "tap-nordvpn",
    "wintun",
    "wireguard",
    "amneziawg",
    "openvpn",
    "outline",
    "hiddify",
    "mihomo",
    "clash",
    "meta tunnel",
    "sing-tun",
];

/// Антивирусы, которые по умолчанию проверяют HTTPS-соединения.
const HTTPS_SCANNERS: &[&str] = &[
    "kaspersky",
    "eset",
    "avast",
    "avg",
    "bitdefender",
    "dr.web",
    "norton",
    "mcafee",
];

/// Признаки zapret в командах автозагрузки и службах.
const ZAPRET_MARKERS: &[&str] = &["winws", "goodbyedpi", "zapret", "discordfix"];

fn has_marker(text: &str) -> bool {
    let t = text.to_lowercase();
    ZAPRET_MARKERS.iter().any(|m| t.contains(m))
}

/// Каталоги KVT в нижнем регистре и с `\\` на конце (см. [`own_dirs`]).
pub struct OwnDirs(Vec<String>);

/// Каталоги, файлы из которых принадлежат KVT: каталог программы и
/// `ProgramData\\KVT` (обновлённый комплект zapret).
pub fn own_dirs<S: AsRef<str>>(dirs: &[S]) -> OwnDirs {
    OwnDirs(
        dirs.iter()
            .map(|d| normalize_dir(d.as_ref()))
            .filter(|d| !d.is_empty())
            .collect(),
    )
}

/// Путь (или командная строка) указывает внутрь каталога KVT.
fn is_own(path: &str, own: &OwnDirs) -> bool {
    let p = path.to_lowercase().replace('/', "\\");
    own.0.iter().any(|d| p.contains(d.as_str()))
}

/// Служба zapret другой сборки (не KVT).
pub fn is_foreign_zapret_service(s: &Service, own: &OwnDirs) -> bool {
    has_marker(&format!("{} {} {}", s.name, s.display_name, s.path)) && !is_own(&s.path, own)
}

/// Запись автозагрузки, которая запускает чужой zapret и ещё не отключена.
pub fn is_zapret_autostart(a: &Autostart, own: &OwnDirs) -> bool {
    !a.disabled && has_marker(&format!("{} {}", a.name, a.command)) && !is_own(&a.command, own)
}

/// Процесс другого VPN-клиента или его ядра — только такой можно закрыть по кнопке.
pub fn is_vpn_process_name(image: &str) -> bool {
    let name = image.trim().to_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    VPN_CLIENTS.iter().any(|(n, _)| *n == name) || CORES.contains(&name)
}

pub fn normalize_dir(dir: &str) -> String {
    let d = dir.trim().to_lowercase().replace('/', "\\");
    if d.is_empty() || d.ends_with('\\') {
        d
    } else {
        d + "\\"
    }
}

/// Выводы аудита. Файлы из каталогов `own` принадлежат KVT и чужими не считаются.
pub fn analyze(facts: &Facts, own: &OwnDirs) -> Vec<Finding> {
    let mut out = Vec::new();
    leaks(facts, &mut out);
    conflicts(facts, own, &mut out);
    zapret(facts, own, &mut out);
    out
}

fn leaks(facts: &Facts, out: &mut Vec<Finding>) {
    use Group::Leaks;
    let p = &facts.proxy;
    let pac = p.auto_config_url.trim();
    if p.enable != 0 || !pac.is_empty() {
        let target = if p.enable != 0 && !p.server.trim().is_empty() {
            p.server.trim().to_owned()
        } else {
            format!("сценарий {pac}")
        };
        out.push(
            Finding::new(
                Leaks,
                Level::Warning,
                "Включён системный прокси",
                format!(
                    "Браузеры и другие программы отправляют трафик на {target} — обычно это остаток \
                     другого VPN-клиента. Если та программа закрыта, сайты не открываются; если \
                     запущена — трафик идёт через неё, а не через KVT."
                ),
            )
            .fix(Fix::DisableSystemProxy),
        );
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            "Системный прокси",
            "Не задан: программы выходят в сеть обычным путём, через туннель KVT.",
        ));
    }

    match winhttp_proxy(&facts.winhttp) {
        Some(proxy) => out.push(
            Finding::new(
                Leaks,
                Level::Warning,
                "Прокси WinHTTP",
                format!(
                    "Службы Windows (обновления, Microsoft Store) ходят в сеть через {proxy}. \
                     Обычно это остаток другого VPN-клиента."
                ),
            )
            .fix(Fix::Service(ServiceFix::ResetWinHttpProxy)),
        ),
        None => out.push(Finding::new(
            Leaks,
            Level::Ok,
            "Прокси WinHTTP",
            "Не задан.",
        )),
    }

    let teredo_state = facts.teredo.state.to_lowercase();
    let teredo_off = facts.teredo.kind.eq_ignore_ascii_case("disabled");
    if !teredo_off && matches!(teredo_state.as_str(), "qualified" | "dormant" | "probe") {
        out.push(
            Finding::new(
                Leaks,
                Level::Warning,
                "Включён Teredo",
                "Teredo даёт компьютеру адрес IPv6 через туннель поверх IPv4. Через него сайты \
                 могут увидеть настоящий адрес мимо VPN. Он нужен только старым играм и Xbox Live.",
            )
            .fix(Fix::Service(ServiceFix::DisableTeredo)),
        );
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            "Teredo",
            "Выключен или не используется.",
        ));
    }

    let manual: Vec<String> = facts
        .adapters
        .iter()
        .filter(|a| a.status.eq_ignore_ascii_case("up") && !a.static_dns.trim().is_empty())
        .filter(|a| !is_tunnel_adapter(a))
        .map(|a| {
            let servers = a
                .static_dns
                .split([',', ' '])
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} — {servers}", a.name)
        })
        .collect();
    if manual.is_empty() {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            "DNS сетевых адаптеров",
            "Получается автоматически от роутера.",
        ));
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Info,
            "DNS прописан вручную",
            format!(
                "{}. При подключённом VPN это не мешает: KVT шифрует DNS и отправляет его в \
                 туннель. Без VPN эти серверы видят, какие сайты вы открываете.",
                manual.join("; ")
            ),
        ));
    }

    let own_doh: Vec<String> = facts
        .browsers
        .iter()
        .filter_map(|b| {
            let enabled = match b.browser.as_str() {
                "firefox" => matches!(b.mode.trim(), "2" | "3"),
                _ => b.mode.eq_ignore_ascii_case("secure"),
            };
            enabled.then(|| {
                let resolver = doh_host(&b.templates);
                match resolver {
                    Some(r) => format!("{} ({r})", browser_title(&b.browser)),
                    None => browser_title(&b.browser).to_owned(),
                }
            })
        })
        .collect();
    if own_doh.is_empty() {
        out.push(Finding::new(
            Leaks,
            Level::Ok,
            "DNS в браузерах",
            "Браузеры используют DNS системы — его настраивает KVT.",
        ));
    } else {
        out.push(Finding::new(
            Leaks,
            Level::Info,
            "Браузер использует свой DNS",
            format!(
                "{}: защищённый DNS включён в настройках браузера. Запросы зашифрованы, но \
                 идут мимо DNS KVT — если сайты из списков маршрутизации открываются не так, \
                 выключите «Безопасный DNS» в настройках браузера.",
                own_doh.join(", ")
            ),
        ));
    }
}

fn browser_title(id: &str) -> &str {
    match id {
        "chrome" => "Google Chrome",
        "edge" => "Microsoft Edge",
        "yandex" => "Яндекс Браузер",
        "brave" => "Brave",
        "firefox" => "Firefox",
        other => other,
    }
}

/// Хост первого DoH-шаблона (`https://dns.google/dns-query{?dns}` → `dns.google`).
fn doh_host(templates: &str) -> Option<String> {
    let first = templates.split_whitespace().next()?;
    let host = crate::netlog::host_of(first);
    (!host.is_empty()).then_some(host)
}

fn is_tunnel_adapter(a: &Adapter) -> bool {
    let d = a.description.to_lowercase();
    TUNNEL_ADAPTERS.iter().any(|m| d.contains(m))
}

/// Адаптер KVT (имя задаёт `compile::TUN_INTERFACE`).
fn is_own_adapter(a: &Adapter) -> bool {
    a.name.eq_ignore_ascii_case(crate::compile::TUN_INTERFACE)
}

fn conflicts(facts: &Facts, own: &OwnDirs, out: &mut Vec<Finding>) {
    use Group::Conflicts;
    let mut seen = Vec::new();
    let mut clients = Vec::new();
    for p in &facts.processes {
        let name = p.name.to_lowercase();
        let title = VPN_CLIENTS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, t)| *t)
            .or_else(|| {
                let foreign_core =
                    CORES.contains(&name.as_str()) && !p.path.is_empty() && !is_own(&p.path, own);
                foreign_core.then_some(p.name.as_str())
            });
        if let Some(title) = title {
            if is_own(&p.path, own) || seen.contains(&title) {
                continue;
            }
            seen.push(title);
            clients.push((title.to_owned(), p.pid));
        }
    }
    if clients.is_empty() {
        out.push(Finding::new(
            Conflicts,
            Level::Ok,
            "Другие VPN-клиенты",
            "Не запущены.",
        ));
    }
    for (title, pid) in clients {
        out.push(
            Finding::new(
                Conflicts,
                Level::Warning,
                format!("Запущен {title}"),
                "Два VPN одновременно спорят за маршруты и DNS: часть трафика уходит не туда, \
                 подключение обрывается. Закройте другой клиент, пока работает KVT.",
            )
            .fix(Fix::CloseProcess { pid, name: title }),
        );
    }

    let adapters: Vec<&Adapter> = facts
        .adapters
        .iter()
        .filter(|a| {
            a.status.eq_ignore_ascii_case("up") && is_tunnel_adapter(a) && !is_own_adapter(a)
        })
        .collect();
    if adapters.is_empty() {
        out.push(Finding::new(
            Conflicts,
            Level::Ok,
            "Туннели других VPN",
            "Активных нет.",
        ));
    } else {
        let names: Vec<String> = adapters
            .iter()
            .map(|a| format!("{} ({})", a.name, a.description))
            .collect();
        out.push(Finding::new(
            Conflicts,
            Level::Warning,
            "Активен туннель другого VPN",
            format!(
                "{}. Пока он подключён, трафик может идти через него. Отключите VPN в той программе.",
                names.join(", ")
            ),
        ));
    }

    let scanners: Vec<&String> = facts
        .antivirus
        .iter()
        .filter(|name| {
            let n = name.to_lowercase();
            HTTPS_SCANNERS.iter().any(|s| n.contains(s))
        })
        .collect();
    if scanners.is_empty() {
        out.push(Finding::new(
            Conflicts,
            Level::Ok,
            "Антивирус",
            "Антивирусов, которые перехватывают HTTPS, не найдено.",
        ));
    } else {
        let names: Vec<&str> = scanners.iter().map(|s| s.as_str()).collect();
        out.push(Finding::new(
            Conflicts,
            Level::Info,
            "Антивирус проверяет HTTPS",
            format!(
                "{} может перехватывать защищённые соединения. Если подписки не загружаются или \
                 проверка серверов ошибается, добавьте папку KVT в исключения или выключите \
                 «Проверку защищённых соединений».",
                names.join(", ")
            ),
        ));
    }
}

fn zapret(facts: &Facts, own: &OwnDirs, out: &mut Vec<Finding>) {
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
            "Другие сборки zapret",
            "Не найдены: ни служб, ни запущенных winws, ни автозапуска.",
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
                .map(|s| format!("служба {}", s.name)),
        );
        names.dedup();
        out.push(
            Finding::new(
                Zapret,
                Level::Warning,
                "Работает другая сборка zapret",
                format!(
                    "{}. Два обхода DPI одновременно перехватывают одни и те же пакеты — \
                     режимы «Гибрид» и «Zapret» в KVT работают неправильно.",
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
                format!("Служба {} запускается вместе с Windows", s.name),
                format!(
                    "{} стартует при каждом включении компьютера и мешает zapret в KVT. \
                     Исправление остановит её и переведёт в ручной запуск — ничего не удаляется.",
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
                format!("Автозапуск zapret: {}", a.name),
                format!(
                    "Запись в разделе «{}» запускает другую сборку zapret при входе в Windows. \
                     Исправление отключит её так же, как «Отключить» в «Диспетчере задач».",
                    a.location.title()
                ),
            )
            .fix(fix),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn own() -> OwnDirs {
        own_dirs(&[r"C:\Program Files\KVT", r"C:\ProgramData\KVT"])
    }

    fn find<'a>(f: &'a [Finding], title: &str) -> &'a Finding {
        f.iter()
            .find(|x| x.title.starts_with(title))
            .unwrap_or_else(|| panic!("нет находки «{title}» в {f:#?}"))
    }

    fn winhttp(flags: u32, proxy: &str) -> String {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x28u32.to_le_bytes());
        raw.extend_from_slice(&5u32.to_le_bytes());
        raw.extend_from_slice(&flags.to_le_bytes());
        raw.extend_from_slice(&(proxy.len() as u32).to_le_bytes());
        raw.extend_from_slice(proxy.as_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    #[test]
    fn clean_machine_has_only_ok() {
        let f = analyze(&Facts::default(), &own());
        assert!(f.iter().all(|x| x.level == Level::Ok), "{f:#?}");
        assert!(f.iter().all(|x| x.fix.is_none()));
        for g in [Group::Leaks, Group::Conflicts, Group::Zapret] {
            assert!(f.iter().any(|x| x.group == g));
        }
    }

    #[test]
    fn script_output_is_parsed() {
        let json = r#"{"proxy":{"enable":1,"server":"127.0.0.1:10808","autoConfigUrl":""},
            "winhttp":"","teredo":{"type":"Default","state":"Offline"},
            "adapters":[{"name":"Ethernet","description":"Realtek","status":"Up","staticDns":"8.8.8.8,1.1.1.1"}],
            "processes":[{"pid":42,"name":"v2rayN","path":"C:\\v2rayN\\v2rayN.exe"}],
            "antivirus":["Windows Defender"],
            "services":[],
            "autostart":[{"location":"hkcu_run","name":"zapret","command":"C:\\z\\general.bat","disabled":false}],
            "browsers":[{"browser":"chrome","mode":"secure","templates":"https://dns.google/dns-query{?dns}"}]}"#;
        let facts = parse_facts(&format!("\u{feff}{json}\r\n")).unwrap();
        assert_eq!(facts.processes[0].pid, 42);
        let f = analyze(&facts, &own());
        assert_eq!(
            find(&f, "Включён системный прокси").fix,
            Some(Fix::DisableSystemProxy)
        );
        assert!(find(&f, "Включён системный прокси")
            .detail
            .contains("127.0.0.1:10808"));
        assert!(find(&f, "DNS прописан вручную")
            .detail
            .contains("8.8.8.8, 1.1.1.1"));
        assert_eq!(
            find(&f, "Запущен v2rayN").fix,
            Some(Fix::CloseProcess {
                pid: 42,
                name: "v2rayN".into()
            })
        );
        assert!(find(&f, "Браузер использует свой DNS")
            .detail
            .contains("dns.google"));
        assert!(matches!(
            find(&f, "Автозапуск zapret: zapret").fix,
            Some(Fix::DisableUserAutostart { .. })
        ));
    }

    #[test]
    fn empty_or_broken_output_is_error_not_panic() {
        assert!(parse_facts("").is_err());
        assert!(parse_facts("not json").is_err());
        assert_eq!(parse_facts("{}").unwrap(), Facts::default());
    }

    #[test]
    fn winhttp_proxy_is_read_only_when_flag_set() {
        assert_eq!(
            winhttp_proxy(&winhttp(3, "127.0.0.1:2080")).as_deref(),
            Some("127.0.0.1:2080")
        );
        assert_eq!(winhttp_proxy(&winhttp(1, "")), None);
        assert_eq!(winhttp_proxy(""), None);
        assert_eq!(winhttp_proxy("!!!"), None);
        let facts = Facts {
            winhttp: winhttp(3, "127.0.0.1:2080"),
            ..Default::default()
        };
        assert_eq!(
            find(&analyze(&facts, &own()), "Прокси WinHTTP").fix,
            Some(Fix::Service(ServiceFix::ResetWinHttpProxy))
        );
    }

    #[test]
    fn teredo_only_when_active() {
        let mut facts = Facts {
            teredo: Teredo {
                kind: "Default".into(),
                state: "Qualified".into(),
            },
            ..Default::default()
        };
        assert_eq!(
            find(&analyze(&facts, &own()), "Включён Teredo").level,
            Level::Warning
        );
        facts.teredo = Teredo {
            kind: "Disabled".into(),
            state: "Qualified".into(),
        };
        assert_eq!(find(&analyze(&facts, &own()), "Teredo").level, Level::Ok);
        facts.teredo = Teredo {
            kind: "Default".into(),
            state: "Offline".into(),
        };
        assert_eq!(find(&analyze(&facts, &own()), "Teredo").level, Level::Ok);
    }

    #[test]
    fn own_cores_and_adapter_are_not_conflicts() {
        let facts = Facts {
            processes: vec![
                Process {
                    pid: 1,
                    name: "xray".into(),
                    path: r"C:\Program Files\KVT\cores\xray.exe".into(),
                },
                // Путь неизвестен (ядро запустила служба) — не считаем чужим.
                Process {
                    pid: 2,
                    name: "sing-box".into(),
                    path: String::new(),
                },
                Process {
                    pid: 3,
                    name: "winws".into(),
                    path: r"C:\Program Files\KVT\zapret\bin\winws.exe".into(),
                },
                Process {
                    pid: 4,
                    name: "winws".into(),
                    path: r"C:\ProgramData\KVT\zapret-bundle\bin\winws.exe".into(),
                },
            ],
            adapters: vec![Adapter {
                name: "KVT".into(),
                description: "Wintun Userspace Tunnel".into(),
                status: "Up".into(),
                static_dns: "172.19.0.2".into(),
            }],
            ..Default::default()
        };
        let f = analyze(&facts, &own());
        assert!(f.iter().all(|x| x.level == Level::Ok), "{f:#?}");
    }

    #[test]
    fn foreign_core_and_tunnel_are_reported() {
        let facts = Facts {
            processes: vec![Process {
                pid: 7,
                name: "sing-box".into(),
                path: r"C:\Hiddify\sing-box.exe".into(),
            }],
            adapters: vec![Adapter {
                name: "OpenVPN".into(),
                description: "TAP-Windows Adapter V9".into(),
                status: "Up".into(),
                static_dns: String::new(),
            }],
            ..Default::default()
        };
        let f = analyze(&facts, &own());
        assert_eq!(find(&f, "Запущен sing-box").level, Level::Warning);
        assert_eq!(
            find(&f, "Активен туннель другого VPN").level,
            Level::Warning
        );
    }

    #[test]
    fn https_scanning_antivirus_is_info() {
        let facts = Facts {
            antivirus: vec!["Windows Defender".into(), "Kaspersky Plus".into()],
            ..Default::default()
        };
        let a = find(&analyze(&facts, &own()), "Антивирус проверяет HTTPS").clone();
        assert_eq!(a.level, Level::Info);
        assert!(a.detail.contains("Kaspersky") && !a.detail.contains("Defender"));
    }

    #[test]
    fn foreign_zapret_service_and_autostart() {
        let facts = Facts {
            services: vec![
                Service {
                    name: "zapret".into(),
                    display_name: "zapret".into(),
                    state: "Running".into(),
                    start_mode: "Auto".into(),
                    path: r"C:\zapret\bin\winws.exe --wf-tcp=443".into(),
                },
                Service {
                    name: "kvt-zapret".into(),
                    display_name: String::new(),
                    state: "Running".into(),
                    start_mode: "Auto".into(),
                    path: r"C:\Program Files\KVT\zapret\bin\winws.exe".into(),
                },
            ],
            autostart: vec![
                Autostart {
                    location: Location::Task,
                    name: r"\zapret autostart".into(),
                    command: r"C:\zapret\service.bat".into(),
                    disabled: false,
                },
                Autostart {
                    location: Location::HklmRun,
                    name: "GoodbyeDPI".into(),
                    command: r"C:\gdpi\goodbyedpi.exe".into(),
                    disabled: true,
                },
                Autostart {
                    location: Location::HkcuRun,
                    name: "Telegram".into(),
                    command: r"C:\Telegram\Telegram.exe -autostart".into(),
                    disabled: false,
                },
            ],
            ..Default::default()
        };
        let f = analyze(&facts, &own());
        assert_eq!(
            find(&f, "Работает другая сборка zapret").fix,
            Some(Fix::StopZapret)
        );
        assert_eq!(
            find(&f, "Служба zapret запускается").fix,
            Some(Fix::Service(ServiceFix::DisableZapretService {
                name: "zapret".into()
            }))
        );
        assert!(!f.iter().any(|x| x.title.contains("kvt-zapret")));
        let task_id = facts.autostart[0].id();
        assert_eq!(
            find(&f, "Автозапуск zapret").fix,
            Some(Fix::Service(ServiceFix::DisableAutostart { id: task_id }))
        );
        // Отключённая запись и Telegram — не находки.
        assert_eq!(
            f.iter()
                .filter(|x| x.title.starts_with("Автозапуск"))
                .count(),
            1
        );
    }

    #[test]
    fn autostart_id_is_stable_and_distinct() {
        let a = Autostart {
            location: Location::HkcuRun,
            name: "zapret".into(),
            command: "x".into(),
            disabled: false,
        };
        let mut b = a.clone();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.id().len(), 16);
        b.location = Location::HklmRun;
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn only_vpn_processes_can_be_closed() {
        assert!(is_vpn_process_name("v2rayN.exe"));
        assert!(is_vpn_process_name("sing-box"));
        assert!(!is_vpn_process_name("explorer.exe"));
        assert!(!is_vpn_process_name("kvt.exe"));
    }

    #[test]
    fn firefox_doh_mode_numbers() {
        let mut facts = Facts {
            browsers: vec![BrowserDns {
                browser: "firefox".into(),
                mode: "5".into(),
                templates: String::new(),
            }],
            ..Default::default()
        };
        assert_eq!(
            find(&analyze(&facts, &own()), "DNS в браузерах").level,
            Level::Ok
        );
        facts.browsers[0].mode = "3".into();
        assert_eq!(
            find(&analyze(&facts, &own()), "Браузер использует").level,
            Level::Info
        );
    }

    #[test]
    fn encoded_script_fits_command_line() {
        // Предел командной строки Windows — 32 767 символов.
        let len: usize = powershell_args().iter().map(|a| a.len() + 1).sum();
        assert!(len < 30_000, "{len}");
    }

    #[test]
    fn fix_json_matches_interface() {
        let fix = Fix::Service(ServiceFix::DisableZapretService {
            name: "zapret".into(),
        });
        let json = serde_json::to_value(&fix).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"kind": "service", "action": "disable_zapret_service", "name": "zapret"})
        );
        assert_eq!(serde_json::from_value::<Fix>(json).unwrap(), fix);
        let close: Fix =
            serde_json::from_str(r#"{"kind":"close_process","pid":7,"name":"v2rayN"}"#).unwrap();
        assert_eq!(
            close,
            Fix::CloseProcess {
                pid: 7,
                name: "v2rayN".into()
            }
        );
    }

    #[test]
    fn script_only_reads() {
        for word in [
            "Set-", "Remove-", "New-Item", "Stop-", "Disable-", "reg add", "netsh", "schtasks",
        ] {
            assert!(!SCRIPT.contains(word), "скрипт аудита содержит {word}");
        }
    }
}
