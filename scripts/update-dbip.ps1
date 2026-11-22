# Обновляет локальную базу стран по IP-адресу: DB-IP Country Lite (CC BY 4.0,
# https://db-ip.com). Скачивает месячный CSV, упаковывает в компактный формат
# (crates/kvt-core/src/geo) и пишет presets\dbip-country.bin и описание рядом.
# База вшивается в kvt.exe: обновлять — перед выпуском, раз в месяц-два.
#
#   powershell -ExecutionPolicy Bypass -File scripts\update-dbip.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\update-dbip.ps1 -Month 2026-12
#   powershell -ExecutionPolicy Bypass -File scripts\update-dbip.ps1 -CsvGz C:\path\dbip-country-lite-2026-11.csv.gz
#
# -Sha256 — ожидаемый хэш .csv.gz, если он известен заранее. Хэш скачанного файла
# всегда пишется в presets\dbip-country.txt: так видно, из чего собрана база.

param(
    [string]$Month = (Get-Date).ToUniversalTime().ToString('yyyy-MM'),
    [string]$CsvGz,
    [string]$Sha256
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$name = "dbip-country-lite-$Month.csv.gz"
$url = "https://download.db-ip.com/free/$name"

# Файл — в своём пустом временном каталоге, отдельно от скриптов.
$work = Join-Path ([IO.Path]::GetTempPath()) ("kvt-dbip-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $work | Out-Null

try {
    if ($CsvGz) {
        $gz = (Resolve-Path -LiteralPath $CsvGz).Path
        $name = Split-Path $gz -Leaf
        $url = "https://download.db-ip.com/free/$name"
    } else {
        $gz = Join-Path $work $name
        Write-Host "Скачиваю $url"
        Invoke-WebRequest -Uri $url -OutFile $gz -UseBasicParsing -TimeoutSec 300
    }
    $actual = (Get-FileHash -Algorithm SHA256 $gz).Hash.ToLowerInvariant()
    if ($Sha256 -and $actual -ne $Sha256.ToLowerInvariant()) {
        throw "SHA-256 не совпал для $name`n  ожидался: $Sha256`n  получен:  $actual"
    }
    Write-Host "SHA-256 $actual"

    $csv = Join-Path $work 'dbip.csv'
    $in = [IO.File]::OpenRead($gz)
    try {
        $gzip = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
        $out = [IO.File]::Create($csv)
        try { $gzip.CopyTo($out) } finally { $out.Dispose(); $gzip.Dispose() }
    } finally { $in.Dispose() }

    $bin = Join-Path $root 'presets\dbip-country.bin'
    Push-Location $root
    try {
        $stats = cargo run -q -p kvt-core --example pack_dbip -- $csv $bin
        if ($LASTEXITCODE -ne 0) { throw 'упаковка базы не удалась' }
    } finally { Pop-Location }

    # Описание рядом с базой: ASCII, чтобы не зависеть от кодировки.
    $lines = @(
        "source=$name",
        "url=$url",
        "sha256_csv_gz=$actual",
        'license=CC BY 4.0 https://creativecommons.org/licenses/by/4.0/',
        'attribution=IP Geolocation by DB-IP https://db-ip.com',
        'changes=repacked into the compact KVT format (crates/kvt-core/src/geo)'
    ) + $stats
    $info = Join-Path $root 'presets\dbip-country.txt'
    [IO.File]::WriteAllText($info, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
    Write-Host "готово -> $bin"
    $stats | ForEach-Object { Write-Host "  $_" }
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
