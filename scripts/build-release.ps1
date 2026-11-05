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
# Готовые файлы и их SHA-256 — в target\release\dist.

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
    foreach ($dir in 'cores', 'zapret') {
        Remove-Item -Recurse -Force (Join-Path $release $dir) -ErrorAction SilentlyContinue
    }
    Invoke-Checked 'ядра и Wintun' { powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'fetch-cores.ps1') -Dest (Join-Path $release 'cores') }
    Invoke-Checked 'комплект zapret' { powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'fetch-zapret.ps1') -Dest (Join-Path $release 'zapret') }
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

Push-Location $app
try {
    # npm ci пересоздаёт node_modules — локально это сломало бы запущенный tauri dev.
    if ($env:CI -or -not (Test-Path 'node_modules')) {
        Invoke-Checked 'зависимости интерфейса' { npm ci }
    }
    $configs = @('--config', 'src-tauri/tauri.release.conf.json')
    if ($env:KVT_SIGN_COMMAND) {
        $sign = @{ bundle = @{ windows = @{ signCommand = $env:KVT_SIGN_COMMAND } } } | ConvertTo-Json -Depth 5 -Compress
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
        $offlineConfig = @{ bundle = @{ windows = @{ webviewInstallMode = @{ type = 'offlineInstaller' } } } } | ConvertTo-Json -Depth 5 -Compress
        Invoke-Checked 'установщик со встроенным WebView2' { npx tauri build @configs --config $offlineConfig }
        $setup = Get-ChildItem $nsis -Filter "*_${version}_*-setup.exe" | Select-Object -First 1
        Copy-Item $setup.FullName (Join-Path $dist "KVT-$version-offline-setup.exe")
    }
}
finally {
    Pop-Location
}

$sums = Get-ChildItem $dist -Filter '*.exe' | ForEach-Object {
    "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant())  $($_.Name)"
}
Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Value $sums -Encoding ASCII
Write-Host ''
Write-Host "Готово: $dist"
$sums | ForEach-Object { Write-Host "  $_" }
