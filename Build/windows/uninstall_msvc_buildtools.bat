@echo off
set SILENT=0
if /I "%~1"=="/silent" set SILENT=1

net session >nul 2>&1
if %errorLevel% == 0 goto :admin

echo A pedir elevacao de administrador...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:admin
set VSPATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools

if exist "%VSPATH%\Common7\Tools\LaunchDevCmd.bat" (
    echo A desinstalar Visual Studio Build Tools 2022 em "%VSPATH%" ...
    echo Pode demorar varios minutos.
    "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" uninstall --installPath "%VSPATH%" --passive --norestart
) else (
    echo Visual Studio Build Tools nao encontrado em "%VSPATH%" - nada a fazer.
)

if %SILENT%==0 pause
