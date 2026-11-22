# Отправляет пост из docs\posts в Telegram через Bot API: картинка с подписью (HTML-разметка).
# Нужен, чтобы получить пост в личный чат с ботом и поставить его в отложку руками.
#   powershell -ExecutionPolicy Bypass -File scripts\send-tg-post.ps1 `
#       -Text docs\posts\03-release-0.9.8.html -Image assets\brand\post-0.9.8.png
#
# Токен бота берётся из $env:TG_BOT_TOKEN, а если переменной нет — спрашивается скрытым
# вводом: так он не попадает ни в историю команд, ни в командную строку процесса (запрос
# идёт через HttpClient, а не через curl с адресом в аргументах).
# chat_id — параметр -ChatId или $env:TG_CHAT_ID; если не задан, берётся чат последнего
# сообщения боту (сначала напишите боту /start).
param(
    [Parameter(Mandatory)][string]$Text,
    [string]$Image,
    [string]$ChatId = $env:TG_CHAT_ID
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

$textPath = (Resolve-Path -LiteralPath $Text).Path
$caption = [IO.File]::ReadAllText($textPath, [Text.Encoding]::UTF8).Trim()
$visible = ($caption -replace '<[^>]+>', '').Trim()
# Подпись к картинке в Telegram — не больше 1024 знаков (считаются без разметки).
if ($Image -and $visible.Length -gt 1024) {
    throw "Подпись $($visible.Length) знаков, а к картинке можно не больше 1024: отправьте без -Image."
}

$token = $env:TG_BOT_TOKEN
if (-not $token) {
    $secure = Read-Host 'Токен бота' -AsSecureString
    $token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if (-not $token) { throw 'Токен бота не задан.' }

# Вызов метода Bot API: поля формы и, при необходимости, один файл (поле $FileField).
function Invoke-Bot([string]$Method, [hashtable]$Fields, [string]$FilePath, [string]$FileField) {
    $client = New-Object System.Net.Http.HttpClient
    $form = New-Object System.Net.Http.MultipartFormDataContent
    try {
        foreach ($name in $Fields.Keys) {
            $part = New-Object System.Net.Http.StringContent([string]$Fields[$name], [Text.Encoding]::UTF8)
            $form.Add($part, $name)
        }
        if ($FilePath) {
            $bytes = [IO.File]::ReadAllBytes($FilePath)
            $file = New-Object System.Net.Http.ByteArrayContent(, $bytes)
            $mime = if ($FilePath -match '\.jpe?g$') { 'image/jpeg' } else { 'image/png' }
            $file.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($mime)
            $form.Add($file, $FileField, [IO.Path]::GetFileName($FilePath))
        }
        $resp = $client.PostAsync("https://api.telegram.org/bot$token/$Method", $form).GetAwaiter().GetResult()
        $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    } finally {
        $form.Dispose()
        $client.Dispose()
    }
    $json = $body | ConvertFrom-Json
    if (-not $json.ok) { throw "Telegram отклонил ${Method}: $($json.description)" }
    return $json
}

if (-not $ChatId) {
    $updates = Invoke-Bot 'getUpdates' @{}
    $last = $updates.result | Where-Object { $_.message } | Select-Object -Last 1
    if (-not $last) { throw 'chat_id не найден: напишите боту /start и повторите, либо задайте -ChatId.' }
    $ChatId = [string]$last.message.chat.id
}

if ($Image) {
    $imagePath = (Resolve-Path -LiteralPath $Image).Path
    $res = Invoke-Bot 'sendPhoto' @{ chat_id = $ChatId; parse_mode = 'HTML'; caption = $caption } $imagePath 'photo'
} else {
    $res = Invoke-Bot 'sendMessage' @{ chat_id = $ChatId; parse_mode = 'HTML'; text = $caption }
}
Write-Host "Отправлено: сообщение $($res.result.message_id) в чат $ChatId."
