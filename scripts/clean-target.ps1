# Убирает из target устаревшие сборки своих крейтов: target иначе растёт на десятки ГБ.
#   powershell -ExecutionPolicy Bypass -File scripts\clean-target.ps1 [-Keep 5] [-Quiet]
# dev.ps1 вызывает его сам при каждом запуске.
#
# Cargo кладёт каждый вариант сборки крейта (build/test/clippy, `-p` или `--workspace`,
# новые версии зависимостей) в отдельный каталог с хешем и старые не удаляет. Больше всего
# копится в incremental (по сотне каталогов kvt_core) и в deps (старые rlib/exe/pdb).
# Скрипт оставляет $Keep последних вариантов каждого своего крейта, чужие зависимости не
# трогает. Удалённое просто пересоберётся. Профиль, который сейчас собирается, пропускается.
param(
    [int]$Keep = 5,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$target = Join-Path (Split-Path -Parent $PSScriptRoot) 'target'
if (-not (Test-Path $target)) { return }

$script:freed = 0L

function Remove-Entry($item) {
    $size = if ($item.PSIsContainer) {
        (Get-ChildItem $item.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
            Measure-Object Length -Sum).Sum
    } else { $item.Length }
    try {
        Remove-Item $item.FullName -Recurse -Force -ErrorAction Stop
        $script:freed += [long]$size
    } catch {
        # Файл занят (например, запущен тест) — уберётся в следующий раз.
    }
}

# Cargo держит target\<профиль>\.cargo-lock открытым всё время сборки.
function Test-Busy($profileDir) {
    $lock = Join-Path $profileDir '.cargo-lock'
    if (-not (Test-Path $lock)) { return $false }
    try {
        $stream = [IO.File]::Open($lock, 'Open', 'ReadWrite', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

$profiles = @('debug', 'release', 'rust-analyzer\debug', 'rust-analyzer\release') |
    ForEach-Object { Join-Path $target $_ } |
    Where-Object { Test-Path $_ }

foreach ($dir in $profiles) {
    if (Test-Busy $dir) {
        if (-not $Quiet) { Write-Host "Идёт сборка в $dir — пропускаю." }
        continue
    }

    # incremental: <крейт>-<хеш>; время каталога меняется при каждой сборке варианта.
    $own = @{}
    $incremental = Join-Path $dir 'incremental'
    if (Test-Path $incremental) {
        Get-ChildItem $incremental -Directory | Group-Object { $_.Name -replace '-[^-]+$', '' } |
            ForEach-Object {
                $own[$_.Name] = $true
                $_.Group | Sort-Object LastWriteTime -Descending | Select-Object -Skip $Keep |
                    ForEach-Object { Remove-Entry $_ }
            }
    }

    # deps: файлы своих крейтов (у них есть incremental) — <имя>-<хеш>.<rlib|rmeta|exe|pdb|d>.
    $deps = Join-Path $dir 'deps'
    if (-not (Test-Path $deps) -or $own.Count -eq 0) { continue }
    $files = Get-ChildItem $deps -File
    $variants = @{}
    foreach ($f in $files) {
        if ($f.Name -match '^(?:lib)?([a-z0-9_]+)-([0-9a-f]{16})\.') {
            if (-not $own.ContainsKey($Matches[1])) { continue }
            $key = $Matches[1]
            $hash = $Matches[2]
            if (-not $variants.ContainsKey($key)) { $variants[$key] = @{} }
            if (-not $variants[$key].ContainsKey($hash)) {
                $variants[$key][$hash] = New-Object System.Collections.ArrayList
            }
            [void]$variants[$key][$hash].Add($f)
        } elseif ($f.Name -like '*.rcgu.o' -and $f.LastWriteTime -lt (Get-Date).AddHours(-1)) {
            # Объектные файлы прерванной сборки: rustc удаляет их сам, если доходит до конца.
            Remove-Entry $f
        }
    }
    foreach ($crate in $variants.Values) {
        $crate.GetEnumerator() |
            Sort-Object { ($_.Value | ForEach-Object { $_.LastWriteTime.Ticks } | Measure-Object -Maximum).Maximum } -Descending |
            Select-Object -Skip $Keep |
            ForEach-Object { foreach ($f in $_.Value) { Remove-Entry $f } }
    }
}

if ($script:freed -gt 0 -or -not $Quiet) {
    Write-Host ('target: убрано {0:N1} ГБ устаревших сборок.' -f ($script:freed / 1GB))
}
