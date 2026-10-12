@echo off
rem ProxyTool avtozapusk o'rnatish: kompyuter yoqilib, tizimga kirilgach oynasiz fonda ishga tushadi,
rem ishdan chiqsa 5 daqiqa ichida o'zi qayta ishga tushadi. Administrator huquqi bir marta so'raladi.
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrator huquqi so'ralmoqda...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PYW="
for /f "delims=" %%i in ('where pythonw 2^>nul') do (
    if not defined PYW set "PYW=%%i"
)
if not defined PYW (
    echo [XATO] pythonw.exe topilmadi. Python o'rnatilganini va PATH ga qo'shilganini tekshiring.
    pause
    exit /b 1
)

echo Python: %PYW%
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0autostart.ps1" -Action Install -Pythonw "%PYW%" -Script "%~dp0proxy_tool.py"
echo.
echo Sayt: http://127.0.0.1:1805
echo Ma'lumotlar: %APPDATA%\ProxyTool
pause
endlocal
