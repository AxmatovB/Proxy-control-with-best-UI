# ProxyTool - helper for ProxyTool.bat / Install-Autostart.bat / Uninstall-Autostart.bat
# (ASCII only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI)
param(
    [Parameter(Mandatory = $true)][ValidateSet('Install', 'Uninstall', 'Stop')][string]$Action,
    [string]$Pythonw,
    [string]$Script
)

$MainTask = 'ProxyTool'            # starts at logon, restarts on failure
$WatchTask = 'ProxyTool-Watchdog'  # every 5 min: starts the server if it is not running (respects manual stop)
$Port = 1805
$DataDir = Join-Path $env:APPDATA 'ProxyTool'
$StopFlag = Join-Path $DataDir 'stopped.flag'

function Stop-Server {
    # Stop the tasks first, otherwise Task Scheduler treats a killed process as a failure and restarts it.
    foreach ($t in $MainTask, $WatchTask) {
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
    Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    # Also kill any leftover copies (e.g. a duplicate started earlier) by command line
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*proxy_tool.py*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

switch ($Action) {
    'Install' {
        if (-not (Test-Path $Pythonw)) { throw "pythonw.exe not found: $Pythonw" }
        if (-not (Test-Path $Script))  { throw "proxy_tool.py not found: $Script" }
        $user = "$env:USERDOMAIN\$env:USERNAME"
        $dir = Split-Path $Script

        # Highest = elevated without a UAC prompt (needed for remote PCs and some registry writes)
        $prin = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
        $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -MultipleInstances IgnoreNew `
            -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero)

        # Main task: at every logon (a normal start also clears the "stopped manually" flag)
        $actMain = New-ScheduledTaskAction -Execute $Pythonw -WorkingDirectory $dir `
            -Argument ('"{0}" --no-browser' -f $Script)
        Register-ScheduledTask -TaskName $MainTask -Action $actMain `
            -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $user) -Principal $prin -Settings $set `
            -Description 'ProxyTool web panel (port 1805), hidden, starts at logon' -Force | Out-Null

        # Watchdog: every 5 minutes; does nothing if the server is running or was stopped manually
        $actWatch = New-ScheduledTaskAction -Execute $Pythonw -WorkingDirectory $dir `
            -Argument ('"{0}" --no-browser --respect-stop' -f $Script)
        $trgWatch = New-ScheduledTaskTrigger -Once -At (Get-Date) `
            -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
        Register-ScheduledTask -TaskName $WatchTask -Action $actWatch -Trigger $trgWatch -Principal $prin `
            -Settings $set -Description 'ProxyTool watchdog: restarts the server after a crash' -Force | Out-Null

        Stop-Server
        Remove-Item -LiteralPath $StopFlag -Force -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName $MainTask
        Start-Sleep -Seconds 2
        $listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($listening) { Write-Host "OK: autostart installed and server is running on port $Port." }
        else { Write-Host "Autostart installed, but port $Port is not listening yet (wait a few seconds / see $DataDir\crash.log)." }
    }
    'Uninstall' {
        foreach ($t in $MainTask, $WatchTask) {
            if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
                Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $t -Confirm:$false
                Write-Host "Task '$t' removed."
            }
        }
        Stop-Server
        Write-Host "Autostart removed, server stopped."
    }
    'Stop' {
        New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
        Set-Content -LiteralPath $StopFlag -Value (Get-Date -Format s) -Encoding ASCII
        Stop-Server
        Write-Host "Server stopped. It will not be restarted by the watchdog until you start it again (ProxyTool.bat -> 1) or log on again."
    }
}
