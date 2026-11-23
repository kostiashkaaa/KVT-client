# Скачивает комплект zapret (Flowseal/zapret-discord-youtube) для разработки.
# Версия и SHA-256 зафиксированы: при несовпадении хэша скрипт останавливается.
# .bat-файлы кладутся как данные: KVT их не запускает, а берёт из них аргументы winws.
#
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-zapret.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-zapret.ps1 -Dest target\release\zapret

param(
    [string]$Dest = (Join-Path $PSScriptRoot '..\target\debug\zapret')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$version = '1.10.4'
$archive = @{
    Url    = "https://github.com/Flowseal/zapret-discord-youtube/releases/download/$version/zapret-discord-youtube-$version.zip"
    Sha256 = '291af673bd0238506f9548e0e94ca0abf244000f4c9a06960544fb01c5f97b34'
}
# В архиве нет файла лицензии — берём его из репозитория по тегу релиза.
$license = @{
    Url    = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/$version/LICENSE.txt"
    Sha256 = 'fe3983a1e91206ad1a530bcfae01fad207020cb61882edd62c1e3cb5f8d5d430'
}
# Тексты лицензий библиотек из комплекта, по тегам, а не по ветке: WinDivert 2.2.2
# (драйвер 2.2 из комплекта; LGPL-3.0 или GPL-2.0) и Cygwin 3.4.10, как cygwin1.dll
# (LGPL-3.0+ с исключением о линковке). Кладутся в licenses\, build-release.ps1 переносит
# их в папку лицензий установщика.
$dependencyLicenses = @(
    @{
        Name   = 'WinDivert-LICENSE.txt'
        Url    = 'https://raw.githubusercontent.com/basil00/WinDivert/v2.2.2/LICENSE'
        Sha256 = '14a0cb5214d536e4fdae6aa3f5696f981eeda106cd026e9794bba489ee79d628'
    },
    @{
        Name   = 'Cygwin-CYGWIN_LICENSE.txt'
        Url    = 'https://raw.githubusercontent.com/cygwin/cygwin/cygwin-3.4.10/winsup/CYGWIN_LICENSE'
        Sha256 = '794433752103cf4bbb4a84a1bdb8fbc150abb1762704bb35fecc9f7f820be984'
    },
    @{
        Name   = 'Cygwin-COPYING.LIB.txt'
        Url    = 'https://raw.githubusercontent.com/cygwin/cygwin/cygwin-3.4.10/winsup/COPYING.LIB'
        Sha256 = 'da7eabb7bafdf7d3ae5e9f223aa5bdc1eece45ac569dc21b3b037520b4464768'
    },
    @{
        Name   = 'Cygwin-COPYING.txt'
        Url    = 'https://raw.githubusercontent.com/cygwin/cygwin/cygwin-3.4.10/winsup/COPYING'
        Sha256 = '8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903'
    }
)
# Те же хэши проверяет служба перед запуском (kvt_core::zapret::BINARY_HASHES).
$binaries = @{
    'winws.exe'       = 'affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188'
    'WinDivert.dll'   = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
    'cygwin1.dll'     = '103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b'
}

function Get-Verified([string]$Url, [string]$Expected, [string]$OutFile) {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 120
    $actual = (Get-FileHash -Algorithm SHA256 $OutFile).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 не совпал для $Url`n  ожидался: $Expected`n  получен:  $actual"
    }
}

# Архив — в своём пустом временном каталоге, отдельно от скриптов.
$work = Join-Path ([IO.Path]::GetTempPath()) ("kvt-zapret-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $work | Out-Null

try {
    Write-Host "zapret-discord-youtube $version"
    $zip = Join-Path $work 'zapret.zip'
    Get-Verified $archive.Url $archive.Sha256 $zip
    $unpacked = Join-Path $work 'x'
    Expand-Archive -Path $zip -DestinationPath $unpacked -Force
    $root = Join-Path $unpacked "zapret-discord-youtube-$version"

    foreach ($sub in 'bin', 'lists', 'strategies') {
        New-Item -ItemType Directory -Force (Join-Path $Dest $sub) | Out-Null
    }
    Copy-Item (Join-Path $root 'bin\*') (Join-Path $Dest 'bin') -Force
    Copy-Item (Join-Path $root 'lists\*') (Join-Path $Dest 'lists') -Force
    Get-ChildItem $root -Filter 'general*.bat' | Copy-Item -Destination (Join-Path $Dest 'strategies') -Force

    foreach ($name in $binaries.Keys) {
        $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $Dest "bin\$name")).Hash.ToLowerInvariant()
        if ($actual -ne $binaries[$name]) {
            throw "SHA-256 не совпал для $name"
        }
    }

    Get-Verified $license.Url $license.Sha256 (Join-Path $Dest 'LICENSE.txt')
    $licensesDir = Join-Path $Dest 'licenses'
    New-Item -ItemType Directory -Force $licensesDir | Out-Null
    foreach ($l in $dependencyLicenses) {
        Get-Verified $l.Url $l.Sha256 (Join-Path $licensesDir $l.Name)
    }
    Set-Content -Path (Join-Path $Dest 'VERSION') -Value $version -Encoding ASCII
    $count = (Get-ChildItem (Join-Path $Dest 'strategies') -Filter '*.bat').Count
    Write-Host "  готово: $count стратегий -> $Dest"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
