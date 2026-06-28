@echo off
set SILENT=0
if /I "%~1"=="/silent" set SILENT=1

net session >nul 2>&1
if %errorLevel% == 0 goto :admin

echo A pedir elevacao de administrador...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:admin
echo A desinstalar Eclipse Temurin JDK 17 via winget...
winget uninstall EclipseAdoptium.Temurin.17.JDK --accept-source-agreements --disable-interactivity

if %SILENT%==0 pause
