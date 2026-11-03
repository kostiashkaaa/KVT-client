# Скачивает ядра (Xray, sing-box) и Wintun для разработки.
# Списки маршрутизации скачивает служба: kvt-service update-rules --dir <каталог>.
# Версии и SHA-256 зафиксированы: при несовпадении хэша скрипт останавливается.
#
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-cores.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-cores.ps1 -Dest target\release\cores

param(
    [string]$Dest = (Join-Path $PSScriptRoot '..\target\debug\cores')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$packages = @(
    @{
        Name   = 'Xray v26.10.29'
        Url    = 'https://github.com/XTLS/Xray-core/releases/download/v26.10.29/Xray-windows-64.zip'
        Sha256 = 'fce33e81cccf50e7aab572b175519a50b5e0f9d2f5c8d1ed73012ea5c9ad4d58'
        Files  = @{ 'xray.exe' = 'xray.exe' }
    },
    @{
        Name   = 'sing-box 1.14.4'
        Url    = 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip'
        Sha256 = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
        Files  = @{ 'sing-box-1.14.4-windows-amd64\sing-box.exe' = 'sing-box.exe' }
    }
)

# Wintun нужен Xray для TUN на Windows.
$wintun = @{
    Url    = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
    Sha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
}

# Каждый архив — в своём пустом временном каталоге, отдельно от скриптов.
$work = Join-Path ([IO.Path]::GetTempPath()) ("kvt-fetch-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $work | Out-Null
New-Item -ItemType Directory -Force $Dest | Out-Null

function Get-Verified([string]$Url, [string]$Expected, [string]$OutFile) {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 120
    $actual = (Get-FileHash -Algorithm SHA256 $OutFile).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 не совпал для $Url`n  ожидался: $Expected`n  получен:  $actual"
    }
}

# Подлинный wintun.dll: действительная подпись WireGuard LLC и 64-битный PE (AMD64).
function Test-WintunDll([string]$Path) {
    $sig = Get-AuthenticodeSignature $Path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '^CN=WireGuard LLC,') {
        return $false
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    return [BitConverter]::ToUInt16($bytes, $pe + 4) -eq 0x8664
}

try {
    foreach ($p in $packages) {
        Write-Host "-> $($p.Name)"
        $dir = Join-Path $work ([guid]::NewGuid())
        New-Item -ItemType Directory $dir | Out-Null
        $zip = Join-Path $dir 'package.zip'
        Get-Verified $p.Url $p.Sha256 $zip
        $unpacked = Join-Path $dir 'unpacked'
        Expand-Archive -Path $zip -DestinationPath $unpacked
        foreach ($entry in $p.Files.GetEnumerator()) {
            Copy-Item -Force (Join-Path $unpacked $entry.Key) (Join-Path $Dest $entry.Value)
        }
    }

    Write-Host '-> Wintun 0.14.1'
    $wintunOut = Join-Path $Dest 'wintun.dll'
    try {
        $dir = Join-Path $work 'wintun'
        New-Item -ItemType Directory $dir | Out-Null
        Get-Verified $wintun.Url $wintun.Sha256 (Join-Path $dir 'wintun.zip')
        Expand-Archive -Path (Join-Path $dir 'wintun.zip') -DestinationPath (Join-Path $dir 'unpacked')
        Copy-Item -Force (Join-Path $dir 'unpacked\wintun\bin\amd64\wintun.dll') $wintunOut
    }
    catch {
        # wintun.net из России часто «замерзает» после первых ~16 КБ.
        Write-Warning "wintun.net недоступен: $($_.Exception.Message)"
        Write-Warning 'Ищу уже установленную копию с подписью WireGuard LLC...'
        $found = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA) |
            Where-Object { $_ -and (Test-Path $_) } |
            ForEach-Object { Get-ChildItem -Path $_ -Filter wintun.dll -Recurse -Depth 4 -ErrorAction SilentlyContinue } |
            Where-Object { Test-WintunDll $_.FullName } |
            Select-Object -First 1
        if (-not $found) {
            throw "Не удалось получить wintun.dll. Скачайте $($wintun.Url) через VPN и положите bin\amd64\wintun.dll в $Dest"
        }
        Write-Host "   взят $($found.FullName)"
        Copy-Item -Force $found.FullName $wintunOut
    }
    if (-not (Test-WintunDll $wintunOut)) { throw 'wintun.dll не прошёл проверку подписи' }

    Write-Host "Готово: $((Resolve-Path $Dest).Path)"
    Write-Host "Списки для тестов: cargo run -p kvt-service -- update-rules --dir target\debug\cores\rules"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
