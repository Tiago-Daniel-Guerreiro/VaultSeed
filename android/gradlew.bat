@echo off
setlocal

where gradle >nul 2>nul
if errorlevel 1 (
    echo gradle is required to build the Android APK scaffold. 1>&2
    exit /b 1
)

gradle -p "%~dp0" %*