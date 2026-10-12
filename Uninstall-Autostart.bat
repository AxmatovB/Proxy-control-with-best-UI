@echo off
rem ProxyTool avtozapuskini o'chirish va ishlayotgan serverni to'xtatish.
rem Sozlamalar va IP ro'yxati (%APPDATA%\ProxyTool) o'chirilmaydi.
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrator huquqi so'ralmoqda...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0autostart.ps1" -Action Uninstall
echo.
pause
endlocal
