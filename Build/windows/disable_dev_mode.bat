@echo off
set SILENT=0
if /I "%~1"=="/silent" set SILENT=1

net session >nul 2>&1
if %errorLevel% == 0 goto :admin

echo A pedir elevação de administrador...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:admin
echo A desactivar o Developer Mode do Windows...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevMode /t REG_DWORD /d 0 /f

if %SILENT%==0 pause
