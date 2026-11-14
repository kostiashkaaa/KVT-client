# Запуск KVT для разработки (задачи VS Code: Ctrl+Shift+B).
#   dev.ps1            — окно KVT справа на экране: правки UI видны сразу, правки Rust
#                        пересобирают и перезапускают окно.
#   dev.ps1 -Service   — служба в консоли с правами администратора (без прав — спросит UAC
#                        и откроет отдельное окно). Установленная KVTService на это время
#                        останавливается и после выхода запускается снова.
param([switch]$Service)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Cargo не удаляет старые варианты сборок, и target разрастается на десятки ГБ.
function Clear-Target {
    try {
        & (Join-Path $PSScriptRoot 'clean-target.ps1') -Quiet
    } catch {
        Write-Host "Не удалось почистить target: $_" -ForegroundColor Yellow
    }
}

# Ядра, zapret и прокси Telegram лежат рядом с exe в target\debug; после cargo clean
# их нет, и «Подключить» падает с «не удалось запустить …\cores\xray.exe».
function Install-Bundles {
    $debug = Join-Path $root 'target\debug'
    $bundles = @(
        @{ File = 'cores\xray.exe'; Script = 'fetch-cores.ps1'; Dir = 'cores' },
        @{ File = 'zapret\bin\winws.exe'; Script = 'fetch-zapret.ps1'; Dir = 'zapret' },
        @{ File = 'tgproxy\tg-ws-proxy.exe'; Script = 'fetch-tgproxy.ps1'; Dir = 'tgproxy' }
    )
    foreach ($b in $bundles) {
        if (Test-Path (Join-Path $debug $b.File)) { continue }
        Write-Host "Нет $($b.File) — скачиваю ($($b.Script))…"
        & (Join-Path $PSScriptRoot $b.Script) -Dest (Join-Path $debug $b.Dir)
    }
}

if ($Service) {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        try {
            Start-Process powershell -Verb RunAs -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"", '-Service'
            )
            Write-Host 'Служба запускается в отдельном окне администратора. Остановить — Ctrl+C в нём.'
        } catch {
            Write-Host 'Без прав администратора служба не запустится: запрос UAC отклонён.' -ForegroundColor Yellow
        }
        return
    }

    $Host.UI.RawUI.WindowTitle = 'KVT: служба (разработка)'
    Clear-Target
    Install-Bundles
    # Установленная служба занимает тот же pipe и не примет kvt.exe из target\debug.
    $installed = Get-Service KVTService -ErrorAction SilentlyContinue
    $wasRunning = $null -ne $installed -and $installed.Status -eq 'Running'
    if ($wasRunning) {
        Write-Host 'Останавливаю установленную службу KVTService на время разработки…'
        Stop-Service KVTService
    }
    try {
        Set-Location $root
        cargo run -p kvt-service -- --console
    } finally {
        if ($wasRunning) {
            Write-Host 'Запускаю установленную службу KVTService обратно…'
            Start-Service KVTService
        }
    }
    return
}

# Окно KVT — один экземпляр: если открыт установленный KVT или окно прошлого запуска,
# новое окно сразу закроется. Поэтому их закрываем.
Get-Process kvt -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "Закрываю запущенный KVT: $($_.Path)"
    Stop-Process -Id $_.Id -ErrorAction SilentlyContinue
}
Clear-Target
Install-Bundles
$env:KVT_DEV_DOCK = 'right'
Set-Location (Join-Path $root 'app')
# Vite уже работает (превью интерфейса в браузере) — окно берёт UI с него, второй не нужен.
if (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue) {
    Write-Host 'Vite уже запущен на порту 5173 — подключаюсь к нему.'
    # Дополнение к конфигу — файлом: JSON в аргументах ломается в кавычках npm и cmd.
    $extra = Join-Path $env:TEMP 'kvt-dev-no-vite.json'
    Set-Content -Path $extra -Value '{"build":{"beforeDevCommand":""}}' -Encoding ascii
    npm run tauri dev -- --config $extra
} else {
    npm run tauri dev
}
