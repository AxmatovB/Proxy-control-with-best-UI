@echo off
rem UAC parol rejimi: administrator huquqi so'ralganda "Ha/Yo'q" o'rniga foydalanuvchi nomi va PAROL so'raladi.
rem   1 = yoqish        0 = avvalgi holatga qaytarish        2 = hozirgi holatni ko'rish
rem Argument bilan:  UAC-Password.bat 1  |  UAC-Password.bat 0  |  UAC-Password.bat 2
rem DIQQAT: bu butun kompyuterning UAC sozlamasi (boshqa dasturlarga ham ta'sir qiladi).
setlocal
set "KEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
set "VAL=ConsentPromptBehaviorAdmin"
set "BK=%APPDATA%\ProxyTool\uac_prev.txt"
set "ACT=%~1"
if defined ACT goto dispatch

echo.
echo   UAC parol rejimi
echo   ---------------------------------------
echo   [1]  Yoqish  (administrator so'ralganda parol so'raydi)
echo   [0]  Qaytarish (avvalgi holat)
echo   [2]  Hozirgi holatni ko'rish
echo.
choice /c 102 /n /m "  Tanlang (1, 0 yoki 2): "
if errorlevel 3 (set "ACT=2" & goto dispatch)
if errorlevel 2 (set "ACT=0" & goto dispatch)
set "ACT=1"

:dispatch
if "%ACT%"=="2" goto status
if "%ACT%"=="1" goto needadmin
if "%ACT%"=="0" goto needadmin
echo Noto'g'ri tanlov: %ACT%  (1, 0 yoki 2 kiriting)
pause
exit /b 1

:needadmin
net session >nul 2>&1
if errorlevel 1 (
    echo Administrator huquqi so'ralmoqda...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%ACT%' -Verb RunAs"
    exit /b
)
if "%ACT%"=="1" goto enable
goto restore

:status
call :readcur
if not defined CUR (
    echo Hozirgi holat: qiymat yo'q ^(Windows standarti: "Ha/Yo'q" oynasi^).
) else if /i "%CUR%"=="0x1" (
    echo Hozirgi holat: YOQILGAN - administrator uchun parol so'raladi ^(secure desktop^).
) else if /i "%CUR%"=="0x3" (
    echo Hozirgi holat: parol so'raladi ^(oddiy oyna^).
) else if /i "%CUR%"=="0x5" (
    echo Hozirgi holat: standart - faqat "Ha/Yo'q" oynasi.
) else (
    echo Hozirgi holat: %VAL% = %CUR%
)
if exist "%BK%" echo Eski qiymat saqlangan: qaytarish uchun "0" ni tanlang.
echo.
pause
exit /b 0

:enable
call :readcur
if /i "%CUR%"=="0x1" (
    echo Allaqachon yoqilgan.
    echo.
    pause
    exit /b 0
)

rem parolsiz hisobda yoqish mumkin emas - o'zingizni bloklab qo'yasiz
powershell -NoProfile -Command "try{ if(-not (Get-LocalUser -Name $env:USERNAME -ErrorAction Stop).PasswordRequired){ exit 2 } }catch{}; exit 0"
if errorlevel 2 (
    echo [XATO] "%USERNAME%" hisobida parol yo'q. Parolsiz hisobda bu rejimni yoqib bo'lmaydi:
    echo        administrator huquqini hech qachon ololmay qolasiz. Avval hisobga parol qo'ying.
    echo.
    pause
    exit /b 1
)

rem kompyuter domenda bo'lsa, siyosatni domen (GPO) qayta yozib qo'yishi mumkin
powershell -NoProfile -Command "if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){ exit 3 } else { exit 0 }"
if errorlevel 3 (
    echo [ESLATMA] Kompyuter domenda. Domen siyosati bu sozlamani keyinroq qayta yozib qo'yishi mumkin.
)

rem eski qiymatni saqlab qo'yamiz (qaytarish uchun)
if not exist "%APPDATA%\ProxyTool" mkdir "%APPDATA%\ProxyTool" >nul 2>&1
if defined CUR (
    >"%BK%" echo %CUR%
) else (
    >"%BK%" echo 0x5
)
reg add "%KEY%" /v %VAL% /t REG_DWORD /d 1 /f >nul
if errorlevel 1 (
    echo [XATO] Sozlamani yozib bo'lmadi.
    echo.
    pause
    exit /b 1
)
call :readcur
echo YOQILDI. Endi administrator huquqi so'ralganda foydalanuvchi nomi va parol kiritiladi.
echo (Qaytarish: shu faylni qayta ochib "0" ni tanlang.)
echo.
pause
exit /b 0

:restore
set "PREV=0x5"
if exist "%BK%" set /p PREV=<"%BK%"
reg add "%KEY%" /v %VAL% /t REG_DWORD /d %PREV% /f >nul
if errorlevel 1 (
    echo [XATO] Sozlamani qaytarib bo'lmadi.
    echo.
    pause
    exit /b 1
)
del "%BK%" >nul 2>&1
echo QAYTARILDI: %VAL% = %PREV%
echo.
pause
exit /b 0

:readcur
set "CUR="
for /f "tokens=3" %%a in ('reg query "%KEY%" /v %VAL% 2^>nul ^| findstr "REG_DWORD"') do set "CUR=%%a"
exit /b 0
