@echo off
rem ProxyTool boshqaruvi:
rem    1 = fonda (oynasiz) ishga tushirish va brauzerda ochish
rem    0 = fondagi sessiyani to'xtatish (kill)
rem Argument bilan ham ishlaydi:  ProxyTool.bat 1   |   ProxyTool.bat 0
rem (ikkinchi argument "quiet" bo'lsa brauzer ochilmaydi)
setlocal
cd /d "%~dp0"

set "ACT=%~1"
set "QUIET=%~2"
if defined ACT goto dispatch

echo.
echo   ProxyTool  (http://127.0.0.1:1805)
echo   ---------------------------------------
echo   [1]  Ishga tushirish (fonda, oynasiz)
echo   [0]  To'xtatish (fondagi sessiyani o'chirish)
echo.
choice /c 10 /n /m "  Tanlang (1 yoki 0): "
if errorlevel 2 (set "ACT=0") else (set "ACT=1")

:dispatch
if "%ACT%"=="0" goto stop
if "%ACT%"=="1" goto start
echo Noto'g'ri tanlov: %ACT%  (1 yoki 0 kiriting)
pause
exit /b 1

:start
rem qo'lda to'xtatish belgisini olib tashlaymiz
del "%APPDATA%\ProxyTool\stopped.flag" >nul 2>&1

netstat -ano | findstr /R /C:":1805 .*LISTENING" >nul
if %errorlevel%==0 goto open

rem Avtozapusk o'rnatilgan bo'lsa - uni ishga tushiramiz (administrator huquqi bilan, UAC so'ramaydi)
schtasks /query /tn ProxyTool >nul 2>&1
if %errorlevel%==0 (
    schtasks /run /tn ProxyTool >nul 2>&1
) else (
    where pythonw >nul 2>&1
    if errorlevel 1 (
        start "" /min python "%~dp0proxy_tool.py" --no-browser
    ) else (
        start "" pythonw "%~dp0proxy_tool.py" --no-browser
    )
)
rem server ko'tarilishini kutamiz (~3 soniya)
ping -n 4 127.0.0.1 >nul

:open
if /i not "%QUIET%"=="quiet" start "" "http://127.0.0.1:1805"
endlocal
exit /b 0

:stop
rem Avtozapusk o'rnatilgan bo'lsa server administrator huquqi bilan ishlaydi - to'xtatish uchun ham admin kerak
schtasks /query /tn ProxyTool >nul 2>&1
if %errorlevel%==0 (
    net session >nul 2>&1
    if errorlevel 1 (
        echo Administrator huquqi so'ralmoqda...
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '0' -Verb RunAs"
        exit /b
    )
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0autostart.ps1" -Action Stop
ping -n 3 127.0.0.1 >nul
endlocal
exit /b 0
