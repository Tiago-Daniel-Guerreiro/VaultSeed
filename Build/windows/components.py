"""Componentes desinstaláveis no Windows

Os três `*_bat` vivem em Build/windows/ (fonte local) e são enviados para o
PROJECT_DIR remoto antes de serem usados - ver
cli/platform_data.py::upload_windows_bats. Servem para pedir elevação UAC de
dentro de um processo PowerShell não-elevado."""

from ..core.component import Component

GRADLE_DIR_GLOB = "gradle-*"
NDK_VERSION = "r27c"

def components(uninstall_msvc_bat: str, uninstall_jdk_bat: str, disable_devmode_bat: str) -> list[Component]:
    return [
        Component(
            "rust", "Rust (rustup, toolchains, targets, cargo-ndk/wasm-pack)",
            ps=(
                '_fase "A desinstalar Rust (rustup)"\n'
                'if (Get-Command rustup -ErrorAction SilentlyContinue) {\n'
                '    rustup self uninstall -y *> $null\n'
                '    if ($LASTEXITCODE -eq 0) { _ok "rustup desinstalado (~/.cargo, ~/.rustup removidos)" } '
                'else { _fail "rustup self uninstall falhou" }\n'
                '} else {\n'
                '    _ok "rustup não estava instalado"\n'
                '}\n\n'
            ),
        ),
        Component(
            "msvc_buildtools", "Visual Studio Build Tools (MSVC / link.exe)",
            note="Requer permissão de administrador (UAC).",
            ps=(
                '_fase "A desinstalar Visual Studio Build Tools"\n'
                '_info "Vai abrir uma janela de UAC no teu ambiente de trabalho, aceita-a (pode demorar vários minutos)…"\n'
                f'$bat = "{uninstall_msvc_bat}"\n'
                'try { Start-Process -FilePath "explorer.exe" -ArgumentList "`"$bat`"" } '
                'catch { _info "Não foi possível abrir o pedido de UAC: $_" }\n'
                '$vswhere = "C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"\n'
                '$vcPath = $null\n'
                'for ($i = 0; $i -lt 180; $i++) {\n'
                '    Start-Sleep -Seconds 10\n'
                '    $vcPath = $null\n'
                '    if (Test-Path $vswhere) {\n'
                '        $vcPath = & $vswhere -latest -products * '
                '-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 '
                '-property installationPath 2>$null\n'
                '    }\n'
                '    if (-not $vcPath) { break }\n'
                '}\n'
                'if ($vcPath) { _fail "MSVC Build Tools ainda presente: $vcPath" } '
                'else { _ok "MSVC Build Tools desinstalado" }\n\n'
            ),
        ),
        Component(
            "devmode", "Developer Mode (registo do Windows)",
            note="Requer permissão de administrador (UAC). Reverte "
                 "AllowDevelopmentWithoutDevMode para 0.",
            ps=(
                '_fase "A desactivar o Developer Mode"\n'
                '_info "Vai abrir uma janela de UAC no teu ambiente de trabalho, aceita-a…"\n'
                f'$bat = "{disable_devmode_bat}"\n'
                'try { Start-Process -FilePath "explorer.exe" -ArgumentList "`"$bat`"" } '
                'catch { _info "Não foi possível abrir o pedido de UAC: $_" }\n'
                '$devMode = 1\n'
                'for ($i = 0; $i -lt 60; $i++) {\n'
                '    Start-Sleep -Seconds 2\n'
                '    $devMode = (Get-ItemProperty -Path '
                '"HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/AppModelUnlock" '
                '-Name AllowDevelopmentWithoutDevMode -ErrorAction SilentlyContinue)'
                '.AllowDevelopmentWithoutDevMode\n'
                '    if ($devMode -ne 1) { break }\n'
                '}\n'
                'if ($devMode -eq 1) { _fail "Developer Mode ainda activo" } '
                'else { _ok "Developer Mode desactivado" }\n\n'
            ),
        ),
        Component(
            "ndk", f"Android NDK {NDK_VERSION}",
            ps=(
                f'_fase "A remover Android NDK {NDK_VERSION}"\n'
                f'Remove-Item -Recurse -Force -Path "$HOME/android-sdk/ndk/{NDK_VERSION}" -ErrorAction SilentlyContinue\n'
                f'_ok "NDK {NDK_VERSION} removido"\n\n'
            ),
        ),
        Component(
            "android_sdk", "Android SDK (cmdline-tools, platforms, build-tools, licenses)",
            ps=(
                '_fase "A remover Android SDK"\n'
                'Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -Path '
                '"$HOME/android-sdk/cmdline-tools", "$HOME/android-sdk/platforms", '
                '"$HOME/android-sdk/build-tools", "$HOME/android-sdk/platform-tools", '
                '"$HOME/android-sdk/licenses"\n'
                'if ((Get-ChildItem "$HOME/android-sdk" -Force -ErrorAction SilentlyContinue '
                '| Measure-Object).Count -eq 0) {\n'
                '    Remove-Item -Force -Path "$HOME/android-sdk" -ErrorAction SilentlyContinue\n'
                '}\n'
                '_ok "Android SDK removido"\n\n'
            ),
        ),
        Component(
            "gradle", f"Gradle ({GRADLE_DIR_GLOB})",
            ps=(
                '_fase "A remover Gradle"\n'
                f'Get-ChildItem -Path "$HOME" -Filter "{GRADLE_DIR_GLOB}" -Directory '
                '-ErrorAction SilentlyContinue | Remove-Item -Recurse -Force\n'
                '_ok "Gradle removido"\n\n'
            ),
        ),
        Component(
            "jdk17", "JDK 17 (Eclipse Temurin)",
            note="Requer permissão de administrador (UAC).",
            ps=(
                '_fase "A desinstalar JDK 17 (Eclipse Temurin)"\n'
                '_info "Vai abrir uma janela de UAC no teu ambiente de trabalho, aceita-a…"\n'
                f'$bat = "{uninstall_jdk_bat}"\n'
                'try { Start-Process -FilePath "explorer.exe" -ArgumentList "`"$bat`"" } '
                'catch { _info "Não foi possível abrir o pedido de UAC: $_" }\n'
                '$adoptium = $null\n'
                'for ($i = 0; $i -lt 90; $i++) {\n'
                '    Start-Sleep -Seconds 10\n'
                '    $adoptium = Get-ChildItem "C:/Program Files/Eclipse Adoptium" -Filter "jdk-17*" '
                '-ErrorAction SilentlyContinue | Select-Object -First 1\n'
                '    if (-not $adoptium) { break }\n'
                '}\n'
                'if ($adoptium) { _fail "JDK 17 ainda presente: $($adoptium.FullName)" } '
                'else { _ok "JDK 17 desinstalado" }\n\n'
            ),
        ),
        Component(
            "vaultseed_dir", "$env:APPDATA/VaultSeed/.vaultseed (env.ps1 + histórico)",
            ps=(
                '_fase "A remover $env:APPDATA/VaultSeed/.vaultseed"\n'
                'Remove-Item -Recurse -Force -Path "$env:APPDATA/VaultSeed/.vaultseed" -ErrorAction SilentlyContinue\n'
                '_ok ".vaultseed removido"\n\n'
            ),
        ),
        Component(
            "cargo_config", "$HOME/.cargo/config.toml (se existir)",
            ps=(
                '_fase "A remover $HOME/.cargo/config.toml"\n'
                'Remove-Item -Force -Path "$HOME/.cargo/config.toml" -ErrorAction SilentlyContinue\n'
                '_ok "config.toml removido"\n\n'
            ),
        ),
    ]
