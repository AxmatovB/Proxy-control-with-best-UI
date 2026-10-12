# ProxyTool - диагностика (только чтение, права администратора не нужны)
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

$Dir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script = Join-Path $Dir 'proxy_tool.py'
$Data   = Join-Path $env:APPDATA 'ProxyTool'
$Port   = 1805
$fix    = New-Object System.Collections.Generic.List[string]

function Head($t) { Write-Host ""; Write-Host "== $t" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [ОК]      $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [ВНИМАНИЕ] $m" -ForegroundColor Yellow }
function Bad($m)  { Write-Host "  [ОШИБКА]  $m" -ForegroundColor Red }
function Info($m) { Write-Host "            $m" -ForegroundColor Gray }

function Api($path) {
    try {
        $r = [Net.WebRequest]::Create("http://127.0.0.1:$Port$path")
        $r.Proxy = $null; $r.Timeout = 3000
        $r.Headers.Add('X-Requested-With', 'ProxyTool')
        $resp = $r.GetResponse()
        $sr = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)
        $txt = $sr.ReadToEnd(); $resp.Close()
        return ($txt | ConvertFrom-Json)
    } catch { return $null }
}

Write-Host "ProxyTool: диагностика" -ForegroundColor White
Write-Host "Папка: $Dir"

# ── 1. Python и файлы ──
Head "1. Python и файлы"
$pyw = (Get-Command pythonw).Source
$py  = (Get-Command python).Source
if ($pyw) { Ok "pythonw.exe найден: $pyw" } else { Bad "pythonw.exe не найден (Python не установлен или не добавлен в PATH)"; $fix.Add("Установите Python 3 с python.org и поставьте галочку 'Add python.exe to PATH', затем снова запустите Install-Autostart.bat.") }
if ($py)  { Info ("версия: " + (& python --version 2>&1)) }
if (Test-Path $Script) { Ok "proxy_tool.py на месте" } else { Bad "proxy_tool.py не найден рядом со скриптом"; $fix.Add("Верните proxy_tool.py в папку $Dir.") }

# ── 2. Автозапуск (Планировщик заданий) ──
Head "2. Автозапуск (Планировщик заданий)"
$installed = 0
foreach ($n in 'ProxyTool', 'ProxyTool-Watchdog') {
    $t = Get-ScheduledTask -TaskName $n
    if (-not $t) { Warn "Задача '$n' не установлена"; continue }
    $installed++
    $i = Get-ScheduledTaskInfo -TaskName $n
    $a = $t.Actions[0]
    $state = [string]$t.State
    if ($state -eq 'Disabled') { Warn "'$n': задача ОТКЛЮЧЕНА"; $fix.Add("Включите задачу '$n' в Планировщике заданий или запустите Install-Autostart.bat заново.") }
    else { Ok "'$n': состояние $state" }
    $res = $i.LastTaskResult
    $resTxt = switch ($res) { 0 { 'успешно' } 267009 { 'выполняется сейчас' } 267011 { 'ещё не запускалась' } 267014 { 'остановлена вручную' } default { ('код 0x{0:X}' -f $res) } }
    Info "последний запуск: $($i.LastRunTime)  результат: $resTxt"
    if (-not (Test-Path $a.Execute)) { Bad "'$n': pythonw.exe по пути '$($a.Execute)' больше не существует"; $fix.Add("Python был обновлён/удалён или перенесён. Снова запустите Install-Autostart.bat.") }
    if ($a.Arguments -match '^"([^"]+)"') {
        $taskScript = $Matches[1]
        if (-not (Test-Path $taskScript)) { Bad "'$n': файл '$taskScript' не найден (папку переместили или переименовали?)"; $fix.Add("Папку ProxyTool переместили. Снова запустите Install-Autostart.bat из новой папки.") }
        elseif ($taskScript -ne $Script) { Warn "'$n' запускает другую копию: $taskScript"; $fix.Add("Автозапуск настроен на другую папку. Запустите Install-Autostart.bat из этой папки, чтобы перенастроить.") }
    }
}
if ($installed -eq 0) { $fix.Add("Автозапуск не установлен. Запустите Install-Autostart.bat (один раз), чтобы сервер стартовал сам после включения компьютера.") }
elseif ($installed -eq 1) { $fix.Add("Установлена только одна из двух задач. Запустите Install-Autostart.bat заново.") }

# ── 3. Сервер ──
Head "3. Сервер (порт $Port)"
$c = Get-NetTCPConnection -LocalPort $Port -State Listen | Select-Object -First 1
$serverUp = $false
if (-not $c) {
    Bad "порт $Port закрыт: сервер не запущен"
    if (Test-Path (Join-Path $Data 'stopped.flag')) { Warn "стоит метка 'остановлено вручную' (ProxyTool.bat → 0)"; $fix.Add("Сервер остановлен вручную. Запустите ProxyTool.bat и нажмите 1.") }
    else { $fix.Add("Сервер не запущен. Запустите ProxyTool.bat и нажмите 1. Если он не стартует, посмотрите crash.log (раздел 4).") }
} else {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)"
    $name = if ($p) { $p.Name } else { '?' }
    Ok "порт $Port слушает процесс $name (PID $($c.OwningProcess))"
    $copies = @(Get-Process -Name pythonw).Count
    if ($copies -gt 1) { Warn "запущено $copies процессов pythonw (должен быть один): есть лишние копии сервера"; $fix.Add("Лишние копии сервера. Запустите ProxyTool.bat → 0 (останавливает все копии), затем ProxyTool.bat → 1.") }
    if ($name -notmatch '^pythonw?\.exe$') { Bad "порт занят ДРУГОЙ программой ($name)"; $fix.Add("Порт $Port занят программой '$name'. Закройте её или освободите порт, затем запустите ProxyTool.bat → 1.") }
    else {
        $serverUp = $true
        $st = Api '/api/state'
        if ($st) {
            Ok "сайт отвечает: http://127.0.0.1:$Port"
            if ($st.admin) { Ok "сервер работает с правами администратора" } else { Warn "сервер работает БЕЗ прав администратора (удалённые ПК могут не работать)"; $fix.Add("Для работы с удалёнными ПК установите автозапуск (Install-Autostart.bat): задача запускает сервер с правами администратора.") }
            if ($st.auto.running) { Ok "автообновление включено, цикл №$($st.auto.cycle)" } else { Info "автообновление выключено" }
        } else { Bad "порт открыт, но сайт не отвечает"; $fix.Add("Сервер завис. Запустите ProxyTool.bat → 0, затем снова ProxyTool.bat → 1.") }
        if ($p -and (Test-Path $Script)) {
            $started = $p.CreationDate; $mod = (Get-Item $Script).LastWriteTime
            if ($started -lt $mod) { Warn "сервер запущен $started, а proxy_tool.py изменён позже ($mod): работает СТАРАЯ версия"; $fix.Add("Работает старая версия. Перезапустите: ProxyTool.bat → 0, затем ProxyTool.bat → 1.") }
            else { Ok "версия сервера актуальна (запущен после последнего изменения файла)" }
        }
    }
}

# ── 4. Данные и журналы ──
Head "4. Данные ($Data)"
if (Test-Path $Data) {
    foreach ($f in Get-ChildItem $Data -File) { Info ("{0,-18} {1,8} Б   {2}" -f $f.Name, $f.Length, $f.LastWriteTime) }
    $crash = Join-Path $Data 'crash.log'
    if (Test-Path $crash) {
        Warn "есть crash.log: сервер падал с ошибкой. Последние строки:"
        Get-Content $crash -Tail 8 -Encoding UTF8 | ForEach-Object { Info $_ }
        $fix.Add("Сервер падал (см. crash.log выше). Пришлите эти строки разработчику; обычно помогает перезапуск ProxyTool.bat → 0 → 1.")
    } else { Ok "crash.log нет: падений не было" }
    $sf = Join-Path $Data 'settings.json'
    if (Test-Path $sf) { try { [void](Get-Content $sf -Raw -Encoding UTF8 | ConvertFrom-Json); Ok "settings.json читается" } catch { Bad "settings.json повреждён"; $fix.Add("Файл settings.json повреждён. Удалите его (настройки сбросятся) и перезапустите сервер.") } }
} else { Info "папка ещё не создана (сервер ни разу не запускался)" }

# ── Итог ──
Head "Итог"
if ($fix.Count -eq 0) { Write-Host "  Всё в порядке: сервер работает, автозапуск настроен." -ForegroundColor Green }
else {
    Write-Host "  Что сделать:" -ForegroundColor Yellow
    $k = 1; foreach ($f in $fix) { Write-Host ("   {0}. {1}" -f $k, $f); $k++ }
}
