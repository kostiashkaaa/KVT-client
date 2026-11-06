# Скачивает прокси для Telegram Desktop (valnesfjord/tg-ws-proxy-rs — Rust-порт
# Flowseal/tg-ws-proxy). Версия и SHA-256 зафиксированы: при несовпадении скрипт
# останавливается. Тот же хэш tg-ws-proxy.exe KVT сверяет перед каждым запуском
# (app/src-tauri/src/tgproxy.rs, EXE_SHA256).
#
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-tgproxy.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-tgproxy.ps1 -Dest target\release\tgproxy

param(
    [string]$Dest = (Join-Path $PSScriptRoot '..\target\debug\tgproxy')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$version = '2.7.0'
$archive = @{
    Url    = "https://github.com/valnesfjord/tg-ws-proxy-rs/releases/download/v$version/tg-ws-proxy-x86_64-pc-windows-gnu.zip"
    Sha256 = '607bd2db7482e24db69fb22d1d9aebc8b2e9c4626458abdea125a9e13bafb311'
}
$license = @{
    Url    = "https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/v$version/LICENSE"
    Sha256 = '161d23808f8995e969bf5ab7c67061e188419faea4ed9769325f8eab04360248'
}
$exeSha256 = '18917ecd9dcaeeec510483b90fbc7bc20c171838c6edfbc8d667e48a6801afad'

function Get-Verified([string]$Url, [string]$Expected, [string]$OutFile) {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 120
    $actual = (Get-FileHash -Algorithm SHA256 $OutFile).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 не совпал для $Url`n  ожидался: $Expected`n  получен:  $actual"
    }
}

# Архив — в своём пустом временном каталоге, отдельно от скриптов.
$work = Join-Path ([IO.Path]::GetTempPath()) ("kvt-tgproxy-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $work | Out-Null

try {
    Write-Host "tg-ws-proxy-rs $version"
    $zip = Join-Path $work 'tgproxy.zip'
    Get-Verified $archive.Url $archive.Sha256 $zip
    $unpacked = Join-Path $work 'x'
    Expand-Archive -Path $zip -DestinationPath $unpacked -Force
    $exe = Get-ChildItem $unpacked -Recurse -Filter 'tg-ws-proxy.exe' | Select-Object -First 1
    if (-not $exe) { throw 'в архиве нет tg-ws-proxy.exe' }
    $actual = (Get-FileHash -Algorithm SHA256 $exe.FullName).Hash.ToLowerInvariant()
    if ($actual -ne $exeSha256) { throw "SHA-256 не совпал для tg-ws-proxy.exe" }

    New-Item -ItemType Directory -Force $Dest | Out-Null
    Copy-Item $exe.FullName (Join-Path $Dest 'tg-ws-proxy.exe') -Force
    Get-Verified $license.Url $license.Sha256 (Join-Path $Dest 'LICENSE.txt')
    Set-Content -Path (Join-Path $Dest 'VERSION') -Value $version -Encoding ASCII
    Write-Host "  готово -> $Dest"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
