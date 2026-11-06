# Собирает установщик KVT: служба, ядра, Wintun, комплект zapret и лицензии в одном
# setup.exe (NSIS, установка в Program Files). То же делает release.yml в GitHub Actions.
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Offline   # + установщик со встроенным WebView2
#   powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -SkipFetch # ядра и zapret уже скачаны
#
# Подпись: если задана переменная KVT_SIGN_COMMAND (команда signtool с %1 вместо пути
# к файлу), подписываются kvt-service.exe, kvt.exe и установщик. Без неё сборка без подписи.
#
# Готовые файлы и их SHA-256 — в target\release\dist: KVT-x.y.z-setup.exe (полная
# установка) и KVT-x.y.z-update.exe (обновление установленного KVT, шаг 5.7).

param(
    [switch]$Offline,
    [switch]$SkipFetch
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$release = Join-Path $root 'target\release'
$app = Join-Path $root 'app'

function Invoke-Checked([string]$What, [scriptblock]$Block) {
    Write-Host "== $What"
    & $Block
    if ($LASTEXITCODE -ne 0) { throw "$What — ошибка (код $LASTEXITCODE)" }
}

function Invoke-Sign([string]$Path) {
    if (-not $env:KVT_SIGN_COMMAND) { return }
    $cmd = $env:KVT_SIGN_COMMAND.Replace('%1', "`"$Path`"")
    Invoke-Checked "подпись $(Split-Path -Leaf $Path)" { cmd /c $cmd }
}

$version = (Get-Content (Join-Path $app 'src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json).version
Write-Host "KVT $version"

Invoke-Checked 'служба (release)' { cargo build --release --locked -p kvt-service --manifest-path (Join-Path $root 'Cargo.toml') }
Invoke-Sign (Join-Path $release 'kvt-service.exe')

if (-not $SkipFetch) {
    foreach ($dir in 'cores', 'zapret', 'tgproxy') {
        Remove-Item -Recurse -Force (Join-Path $release $dir) -ErrorAction SilentlyContinue
    }
    Invoke-Checked 'ядра и Wintun' { powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'fetch-cores.ps1') -Dest (Join-Path $release 'cores') }
    Invoke-Checked 'комплект zapret' { powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'fetch-zapret.ps1') -Dest (Join-Path $release 'zapret') }
    Invoke-Checked 'прокси для Telegram' { powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'fetch-tgproxy.ps1') -Dest (Join-Path $release 'tgproxy') }
}

# Тексты лицензий — в одной папке рядом с kvt.exe («О программе» → «Тексты лицензий»).
$licenses = Join-Path $release 'licenses'
Remove-Item -Recurse -Force $licenses -ErrorAction SilentlyContinue
New-Item -ItemType Directory $licenses | Out-Null
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $licenses 'KVT-LICENSE.txt')
Copy-Item (Join-Path $root 'THIRD-PARTY-NOTICES.md') (Join-Path $licenses 'THIRD-PARTY-NOTICES.md')
$coreLicenses = Join-Path $release 'cores\licenses'
if (Test-Path $coreLicenses) {
    Copy-Item (Join-Path $coreLicenses '*') $licenses
    Remove-Item -Recurse -Force $coreLicenses
}
Copy-Item (Join-Path $release 'zapret\LICENSE.txt') (Join-Path $licenses 'zapret-discord-youtube-LICENSE.txt')
Copy-Item (Join-Path $release 'tgproxy\LICENSE.txt') (Join-Path $licenses 'tg-ws-proxy-rs-LICENSE.txt')

Push-Location $app
try {
    # npm ci пересоздаёт node_modules — локально это сломало бы запущенный tauri dev.
    if ($env:CI -or -not (Test-Path 'node_modules')) {
        Invoke-Checked 'зависимости интерфейса' { npm ci }
    }
    # Свой шаблон NSIS (windows\installer.nsi) — копия из конкретной версии Tauri CLI.
    $cli = (Get-Content 'node_modules\@tauri-apps\cli\package.json' -Raw | ConvertFrom-Json).version
    $template = Get-Content 'src-tauri\windows\installer.nsi' -TotalCount 6 -Encoding UTF8 | Out-String
    if ($template -notmatch "tauri-cli $([regex]::Escape($cli))") {
        throw "Шаблон src-tauri\windows\installer.nsi сделан не для Tauri CLI $cli — обновите его (см. комментарий в начале файла)."
    }
    # Дополнительные настройки Tauri — файлами, а не строкой JSON: при вызове npx
    # (это .cmd) PowerShell 7 срезает кавычки внутри аргумента, и JSON ломается.
    function Write-TauriConfig([string]$Name, [hashtable]$Config) {
        $path = Join-Path $release $Name
        [IO.File]::WriteAllText($path, ($Config | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))
        return $path
    }
    $configs = @('--config', 'src-tauri/tauri.release.conf.json')
    if ($env:KVT_SIGN_COMMAND) {
        $sign = Write-TauriConfig 'tauri.sign.conf.json' @{ bundle = @{ windows = @{ signCommand = $env:KVT_SIGN_COMMAND } } }
        $configs += @('--config', $sign)
    }
    Invoke-Checked 'установщик' { npx tauri build @configs }
    $nsis = Join-Path $release 'bundle\nsis'
    $dist = Join-Path $release 'dist'
    Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
    New-Item -ItemType Directory $dist | Out-Null
    $setup = Get-ChildItem $nsis -Filter "*_${version}_*-setup.exe" | Select-Object -First 1
    if (-not $setup) { throw "установщик не найден в $nsis" }
    Copy-Item $setup.FullName (Join-Path $dist "KVT-$version-setup.exe")

    if ($Offline) {
        $offlineConfig = Write-TauriConfig 'tauri.offline.conf.json' @{ bundle = @{ windows = @{ webviewInstallMode = @{ type = 'offlineInstaller' } } } }
        Invoke-Checked 'установщик со встроенным WebView2' { npx tauri build @configs --config $offlineConfig }
        $setup = Get-ChildItem $nsis -Filter "*_${version}_*-setup.exe" | Select-Object -First 1
        Copy-Item $setup.FullName (Join-Path $dist "KVT-$version-offline-setup.exe")
    }
}
finally {
    Pop-Location
}

# Обновление: kvt.exe и служба всегда, ядра, zapret и прокси Telegram — если изменились с minVersion.
$baseline = Get-Content (Join-Path $PSScriptRoot 'update-baseline.json') -Raw | ConvertFrom-Json
$cores = Get-Content (Join-Path $release 'cores\versions.json') -Raw | ConvertFrom-Json
$coresChanged = $false
foreach ($name in 'xray', 'sing-box', 'wintun') {
    if ($cores.$name -ne $baseline.components.cores.$name) { $coresChanged = $true }
}
$zapretVersion = (Get-Content (Join-Path $release 'zapret\VERSION') -Raw).Trim()
$zapretChanged = $zapretVersion -ne $baseline.components.zapret
$tgproxyVersion = (Get-Content (Join-Path $release 'tgproxy\VERSION') -Raw).Trim()
# В установках до 0.9.3 прокси нет вовсе — поле в baseline пустое, и он входит в обновление.
$tgproxyChanged = $tgproxyVersion -ne $baseline.components.tgproxy
$makensis = Join-Path $env:LOCALAPPDATA 'tauri\NSIS\makensis.exe'
$update = Join-Path $dist "KVT-$version-update.exe"
$defines = @(
    "/DVERSION=$version",
    "/DMIN_VERSION=$($baseline.minVersion)",
    "/DSRC=$release",
    "/DOUTFILE=$update",
    "/DPLUGINS=$(Join-Path $env:LOCALAPPDATA 'tauri\NSIS\Plugins\x86-unicode\additional')",
    "/DICON=$(Join-Path $app 'src-tauri\icons\icon.ico')"
)
if ($coresChanged) { $defines += '/DWITH_CORES' }
if ($zapretChanged) { $defines += '/DWITH_ZAPRET' }
if ($tgproxyChanged) { $defines += '/DWITH_TGPROXY' }
$coresNote = if ($coresChanged) { 'входят' } else { 'не изменились' }
$zapretNote = if ($zapretChanged) { 'входит' } else { 'не изменился' }
$tgproxyNote = if ($tgproxyChanged) { 'входит' } else { 'не изменился' }
Write-Host "обновление от $($baseline.minVersion): ядра $coresNote, zapret $zapretNote, прокси Telegram $tgproxyNote"
Invoke-Checked 'обновление' { & $makensis /V2 /INPUTCHARSET UTF8 @defines (Join-Path $app 'src-tauri\windows\update.nsi') }
Invoke-Sign $update

$sums = Get-ChildItem $dist -Filter '*.exe' | ForEach-Object {
    "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant())  $($_.Name)"
}
Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Value $sums -Encoding ASCII
Write-Host ''
Write-Host "Готово: $dist"
$sums | ForEach-Object { Write-Host "  $_" }
