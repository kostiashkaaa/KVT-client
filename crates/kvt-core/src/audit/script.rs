//! Скрипт сбора фактов и аргументы запуска `powershell.exe`. Разбор его вывода — в
//! `facts`, выводы из фактов — в `analyze`.

/// Скрипт сбора фактов. Ничего не меняет; вывод — одна строка JSON ([`Facts`](super::Facts)).
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
