@echo off
rem ProxyTool diagnostikasi: server, avtozapusk, versiya, jurnallar. Administrator kerak emas, hech narsani o'zgartirmaydi.
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0status.ps1"
echo.
pause
