@echo off
set STATUS_FILE=%TEMP%\vaultseed_setup_admin_status.txt

if /I "%~1"=="/elevated" goto :elevated

net session >nul 2>&1
if %errorLevel% == 0 goto :elevated

del "%STATUS_FILE%" >nul 2>&1
echo A pedir elevacao de administrador (um so pedido para os 3 componentes)...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '/elevated' -Verb RunAs"
exit /b

:elevated
> "%STATUS_FILE%" echo START

set VSPATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools
if exist "%VSPATH%\Common7\Tools\LaunchDevCmd.bat" (
    echo [MSVC] já instalado - a reparar/completar componentes em falta...
    "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify --installPath "%VSPATH%" --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended --passive --norestart
) else (
    echo [MSVC] a instalar Visual Studio Build Tools 2022 ^(pode demorar varios minutos^)...
    winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --includeRecommended --passive --norestart" --accept-package-agreements --accept-source-agreements --disable-interactivity
)
set VCRESULT=
"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\vaultseed_vcpath.txt" 2>nul
for /f "usebackq delims=" %%P in ("%TEMP%\vaultseed_vcpath.txt") do set VCRESULT=%%P
del "%TEMP%\vaultseed_vcpath.txt" >nul 2>&1
if defined VCRESULT (
    echo [MSVC] OK: %VCRESULT%
    >> "%STATUS_FILE%" echo MSVC=OK
) else (
    echo [MSVC] FALHOU.
    >> "%STATUS_FILE%" echo MSVC=FAIL
)

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevMode 2>nul | findstr /C:"0x1" >nul
if %errorLevel% == 0 (
    echo [DevMode] ja activo.
    >> "%STATUS_FILE%" echo DEVMODE=OK
) else (
    echo [DevMode] a activar...
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevMode /t REG_DWORD /d 1 /f >nul
    >> "%STATUS_FILE%" echo DEVMODE=OK
    >> "%STATUS_FILE%" echo DEVMODE_NEEDS_RELOGIN=1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0grant_symlink_privilege.ps1"
if errorlevel 2 (
    echo [Symlink] FALHOU a conceder o privilegio.
    >> "%STATUS_FILE%" echo SYMLINK=FAIL
) else if errorlevel 1 (
    echo [Symlink] privilegio "Criar links simbolicos" concedido agora.
    >> "%STATUS_FILE%" echo SYMLINK=OK
    >> "%STATUS_FILE%" echo SYMLINK_NEEDS_RELOGIN=1
) else (
    echo [Symlink] privilegio "Criar links simbolicos" ja estava concedido.
    >> "%STATUS_FILE%" echo SYMLINK=OK
)

dir /b "C:\Program Files\Eclipse Adoptium\jdk-17*" >nul 2>&1
if %errorLevel% == 0 (
    echo [JDK17] ja instalado.
    >> "%STATUS_FILE%" echo JDK17=OK
) else (
    echo [JDK17] a instalar via winget ^(pode demorar alguns minutos^)...
    winget install EclipseAdoptium.Temurin.17.JDK --accept-package-agreements --accept-source-agreements --disable-interactivity
    dir /b "C:\Program Files\Eclipse Adoptium\jdk-17*" >nul 2>&1
    if %errorLevel% == 0 (
        echo [JDK17] OK.
        >> "%STATUS_FILE%" echo JDK17=OK
    ) else (
        echo [JDK17] FALHOU.
        >> "%STATUS_FILE%" echo JDK17=FAIL
    )
)

>> "%STATUS_FILE%" echo DONE

set NEEDS_RELOGIN=
findstr /C:"DEVMODE_NEEDS_RELOGIN=1" "%STATUS_FILE%" >nul
if %errorLevel% == 0 set NEEDS_RELOGIN=1
findstr /C:"SYMLINK_NEEDS_RELOGIN=1" "%STATUS_FILE%" >nul
if %errorLevel% == 0 set NEEDS_RELOGIN=1
if defined NEEDS_RELOGIN (
    echo.
    echo O Developer Mode e/ou o direito "Criar links simbolicos" foram activados/concedidos agora. Para que as symlinks funcionem ^(necessário para compilar para Android^), e preciso terminar sessão e voltar a entrar ^(ou reiniciar o computador^).
    choice /C SN /T 30 /D N /M "Terminar sessao agora"
    if errorlevel 2 (
        echo Sessão mantida - termina e volta a entrar manualmente quando puderes.
    ) else (
        echo A terminar sessão em 5 segundos...
        shutdown /l /t 5
    )
)

if /I not "%~2"=="/silent" pause
