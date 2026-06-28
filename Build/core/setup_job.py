"""SetupJob: instalação do ambiente de build (Rust, NDK, SDK, Gradle, MSVC, módulo NixOS, …) """

from __future__ import annotations

import base64
import re
from abc import ABC, abstractmethod
from pathlib import Path

from .remote_op import RC_DETACHED, RemoteOp, _ts
from .server import Server
from .setup_snippets import GRADLE_VERSION, RUST_TARGETS, XWIN_PREFETCH, sdk_cmds

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

class SetupBuilder(ABC):
    @abstractmethod
    def pre_steps(self, server: Server) -> None:
        """Usado para comandos que devem correr antes do script remoto"""

    @abstractmethod
    def build_script(self, op: RemoteOp) -> str: ...

def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

_APT_DEPS = " ".join([
    "build-essential", "pkg-config", "libssl-dev", "git", "curl", "unzip", "zip",
    "rsync",
    "libfontconfig1-dev", "libxcb-shape0-dev", "libxcb-xfixes0-dev",
    "libxkbcommon-dev", "libegl1-mesa-dev", "libwayland-dev",
    "libgles2-mesa-dev", "libgtk-3-dev", "clang", "openjdk-17-jdk",
    "ninja-build", "lld", "llvm", "mold",
])

_CROSS_TOOLCHAINS = " ".join([
    "gcc-aarch64-linux-gnu", "g++-aarch64-linux-gnu",
    "gcc-arm-linux-gnueabihf", "g++-arm-linux-gnueabihf",
    "gcc-i686-linux-gnu", "g++-i686-linux-gnu",
])

_FOREIGN_ARCHS = ["arm64", "armhf", "i386"]

_UBUNTU_SOURCES = (
    "Types: deb\n"
    "URIs: http://pt.archive.ubuntu.com/ubuntu/\n"
    "Suites: noble noble-updates noble-backports\n"
    "Components: main restricted universe multiverse\n"
    "Architectures: amd64 i386\n"
    "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n"
    "Types: deb\n"
    "URIs: http://security.ubuntu.com/ubuntu/\n"
    "Suites: noble-security\n"
    "Components: main restricted universe multiverse\n"
    "Architectures: amd64 i386\n"
    "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
)

_PORTS_SOURCES = (
    "Types: deb\n"
    "URIs: http://ports.ubuntu.com/ubuntu-ports/\n"
    "Suites: noble noble-updates noble-backports noble-security\n"
    "Components: main restricted universe multiverse\n"
    "Architectures: arm64 armhf\n"
    "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
)

_MULTIARCH_LIBS_BASE = [
    "libssl-dev", "libfontconfig1-dev", "libfreetype-dev",
    "libxcb-shape0-dev", "libxcb-xfixes0-dev", "libxcb-render0-dev",
    "libxkbcommon-dev", "libegl1-mesa-dev", "libwayland-dev",
    "libgles2-mesa-dev", "libgtk-3-dev",
]

_LINUX_CARGO_CONFIG = (
    "[target.aarch64-unknown-linux-gnu]\n"
    "linker = \"aarch64-linux-gnu-gcc\"\n\n"
    "[target.armv7-unknown-linux-gnueabihf]\n"
    "linker = \"arm-linux-gnueabihf-gcc\"\n\n"
    "[target.i686-unknown-linux-gnu]\n"
    "linker = \"i686-linux-gnu-gcc\"\n"
)

class LinuxSetupBuilder(SetupBuilder):
    def __init__(self, sudo_pass: str):
        self.sudo_pass = sudo_pass

    def pre_steps(self, server: Server) -> None:
        pass

    def build_script(self, op: RemoteOp) -> str:
        multiarch_libs = " ".join(
            f"{pkg}:{arch}" for arch in _FOREIGN_ARCHS for pkg in _MULTIARCH_LIBS_BASE
        )
        foreign_archs_str = " ".join(_FOREIGN_ARCHS)
        sdk_cmds_str = sdk_cmds(java_home=True)
        pass_b64 = _b64(self.sudo_pass)
        N = 12

        return (
            "#!/usr/bin/env bash\n"
            "set -u\n"
            + op.preamble()
            + f"PASS=$(echo {pass_b64} | base64 -d)\n"
            "_sudo() { echo \"$PASS\" | sudo -S -E bash -c \"$*\"; }\n\n"

            f'_fase "Passo 1/{N}: Limpeza de ficheiros no formato antigo"\n'
            "shopt -s nullglob\n"
            "for f in ~/.vaultseed/*.sh ~/.vaultseed/*.log ~/.vaultseed/*.status ~/.vaultseed/*.pid ~/.vaultseed/*.lock; do\n"
            "  rm -f \"$f\" && _info \"Removido (legado): $f\"\n"
            "done\n"
            "if [ -d ~/VaultSeed_Release ]; then\n"
            "  _info 'AVISO: ~/VaultSeed_Release existe (formato antigo). Pode ser removido manualmente.'\n"
            "fi\n"
            "_ok 'Limpeza OK'\n\n"

            f'_fase "Passo 2/{N}: Repositórios multiarch (arm64/armhf/i386)"\n'
            f"_sudo \"echo {_b64(_UBUNTU_SOURCES)} | base64 -d > /etc/apt/sources.list.d/ubuntu.sources\"\n"
            f"_sudo \"echo {_b64(_PORTS_SOURCES)} | base64 -d > /etc/apt/sources.list.d/ubuntu-ports.sources\"\n"
            + "".join(f"_sudo 'dpkg --add-architecture {a}'\n" for a in _FOREIGN_ARCHS)
            + "_sudo 'DEBIAN_FRONTEND=noninteractive apt-get update -qq' "
            "&& _ok 'Repositórios OK' || _fail 'Repositórios: falhou'\n\n"

            f'_fase "Passo 3/{N}: Dependências base + Java 17"\n'
            f"_sudo 'DEBIAN_FRONTEND=noninteractive apt-get install -y {_APT_DEPS}' "
            "&& _ok 'Dependências instaladas' || _fail 'Dependências: falhou'\n\n"

            f'_fase "Passo 4/{N}: Cross-toolchains (aarch64/armv7/i686)"\n'
            f"_sudo 'DEBIAN_FRONTEND=noninteractive apt-get install -y {_CROSS_TOOLCHAINS}' "
            "&& _ok 'Cross-toolchains OK' || _fail 'Cross-toolchains: falhou'\n\n"

            f'_fase "Passo 5/{N}: Libs GUI multiarch (pin systemd + force-overwrite)"\n'
            "V=$(_sudo 'dpkg-query -W -f=\\${Version} libsystemd0:amd64 2>/dev/null') && "
            f"PINS='' && for a in {foreign_archs_str}; do "
            "PINS=\"$PINS libudev1:$a=$V libsystemd0:$a=$V\"; done && "
            "_sudo \"DEBIAN_FRONTEND=noninteractive apt-get install -y "
            "-o Dpkg::Options::=--force-overwrite "
            f"{multiarch_libs} $PINS\" "
            "&& _ok 'Libs GUI multiarch OK' || _fail 'Libs GUI: falhou'\n\n"

            f'_fase "Passo 6/{N}: Rust (rustup)"\n'
            "if command -v rustup >/dev/null 2>&1; then\n"
            "  _ok \"rustup já instalado: $(rustup --version 2>/dev/null)\"\n"
            "else\n"
            "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs "
            "| sh -s -- -y --default-toolchain stable "
            "&& source ~/.cargo/env && _ok 'Rust instalado' || _fail 'Rust: falhou'\n"
            "fi\n"
            "source ~/.cargo/env 2>/dev/null || true\n\n"

            f'_fase "Passo 7/{N}: Targets Rust"\n'
            f"({RUST_TARGETS} && _ok 'Targets OK') || _fail 'Targets: alguns falharam'\n\n"

            f'_fase "Passo 8/{N}: Android NDK r27c"\n'
            "if [ -d \"$HOME/android-sdk/ndk/r27c\" ]; then\n"
            "  _ok 'NDK r27c já existe'\n"
            "else\n"
            "  mkdir -p $HOME/android-sdk/ndk && cd $HOME/android-sdk/ndk && "
            "curl -L https://dl.google.com/android/repository/"
            "android-ndk-r27c-linux.zip -o ndk.zip && "
            "unzip -q ndk.zip && mv android-ndk-r27c r27c && rm -f ndk.zip "
            "&& _ok 'NDK instalado' || _fail 'NDK: falhou'\n"
            "fi\n\n"

            f'_fase "Passo 9/{N}: Android SDK (platforms 34+35)"\n'
            "if [ -d \"$HOME/android-sdk/platforms/android-34\" ]; then\n"
            "  _ok 'Android SDK já instalado'\n"
            "else\n"
            f"  ({sdk_cmds_str} && _ok 'Android SDK instalado') || _fail 'Android SDK: falhou'\n"
            "fi\n\n"

            f'_fase "Passo 10/{N}: Gradle {GRADLE_VERSION}"\n'
            f"GV={GRADLE_VERSION}\n"
            "if [ -d \"$HOME/gradle-$GV\" ]; then\n"
            "  _ok 'Gradle já instalado'\n"
            "else\n"
            "  (cd $HOME && curl -fsSL https://services.gradle.org/distributions/"
            "gradle-$GV-bin.zip -o gradle.zip && "
            "unzip -q gradle.zip -d $HOME && rm -f gradle.zip "
            "&& _ok 'Gradle instalado') || _fail 'Gradle: falhou'\n"
            "fi\n\n"

            f'_fase "Passo 11/{N}: cargo-ndk, cargo-xwin, Windows SDK"\n'
            "(cargo ndk --version >/dev/null 2>&1 || cargo install cargo-ndk --locked) "
            "&& _info 'cargo-ndk OK'\n"
            "(cargo xwin --version >/dev/null 2>&1 || cargo install cargo-xwin --locked) "
            "&& _info 'cargo-xwin OK'\n"
            "if [ -d \"$HOME/.xwin-cache\" ] || [ -d \"$HOME/.cargo/xwin\" ]; then\n"
            "  _ok 'Windows SDK cache já existe'\n"
            "else\n"
            f"  ({XWIN_PREFETCH} && _ok 'Windows SDK OK') || _fail 'XWIN prefetch: falhou (não crítico)'\n"
            "fi\n\n"

            "_info 'A configurar linkers cross …'\n"
            f"mkdir -p $HOME/.cargo && echo {_b64(_LINUX_CARGO_CONFIG)} | base64 -d > $HOME/.cargo/config.toml\n\n"

            "grep -q 'gradle-' ~/.bashrc 2>/dev/null || "
            "echo 'export PATH=\"$PATH:$(ls -d $HOME/gradle-*/bin 2>/dev/null | head -1)\"'"
            " >> ~/.bashrc\n\n"

            f'_fase "Passo 12/{N}: wasm-pack (extensão de browser)"\n'
            "if command -v wasm-pack >/dev/null 2>&1; then\n"
            "  _ok \"wasm-pack já instalado: $(wasm-pack --version 2>/dev/null)\"\n"
            "else\n"
            "  (cargo install wasm-pack --locked && _ok 'wasm-pack instalado') "
            "|| _fail 'wasm-pack: falhou'\n"
            "fi\n\n"

            "_info '══════════════════════════'\n"
            "_info 'SETUP LINUX COMPLETO'\n"
            "_info '══════════════════════════'\n"
            "echo 0 > \"$OP_STATUS\"\n"
        )

class NixosSetupBuilder(SetupBuilder):
    _NIX_MODULE = _REPO_ROOT / "Build" / "nixos" / "vaultseed-system.nix"

    def pre_steps(self, server: Server) -> None:
        self._upload_nixos_module(server)
        self._patch_configuration_nix(server)
        self._nixos_rebuild(server)

    def _upload_nixos_module(self, server: Server) -> None:
        if not self._NIX_MODULE.exists():
            raise FileNotFoundError(f"Não encontrado: {self._NIX_MODULE}")
        content = self._NIX_MODULE.read_text("utf-8")
        b64 = _b64(content)
        _ts("A enviar vaultseed-system.nix -> /etc/nixos/vaultseed.nix …")
        server.run_checked(
            f"echo {b64} | base64 -d | tee /etc/nixos/vaultseed.nix > /dev/null",
            sudo=True,
        )
        _ts("Módulo NixOS enviado.")

    def _patch_configuration_nix(self, server: Server) -> None:
        _ts("A verificar imports do configuration.nix …")
        already = server.capture(
            "grep -q 'vaultseed' /etc/nixos/configuration.nix && echo yes || echo no",
            timeout=10,
        ).strip()
        if already == "yes":
            _ts("  vaultseed.nix já está nos imports - nada a fazer.")
            return

        server.run_checked(
            "cp /etc/nixos/configuration.nix /etc/nixos/configuration.nix.bak-vaultseed",
            sudo=True,
        )

        py_script = (
            "import re, sys\n"
            "p = '/etc/nixos/configuration.nix'\n"
            "t = open(p).read()\n"
            "new, n = re.subn(\n"
            "    r'(imports\\s*=\\s*\\[)',\n"
            "    r'\\1 ./vaultseed.nix',\n"
            "    t, count=1\n"
            ")\n"
            "if n == 0:\n"
            "    sys.stderr.write('PATCH FALHOU: padrao imports=[...] nao encontrado\\n')\n"
            "    sys.exit(1)\n"
            "open(p, 'w').write(new)\n"
            "print('OK')\n"
        )
        server.run_checked(
            f"echo {_b64(py_script)} | base64 -d | python3",
            timeout=15,
            sudo=True,
        )

        preview = server.capture(
            "grep -n 'imports\\|vaultseed' /etc/nixos/configuration.nix | head -8",
            timeout=10,
        )
        _ts(f"  configuration.nix após patch:\n{preview}")

    def _nixos_rebuild(self, server: Server) -> None:
        _ts("nixos-rebuild switch … (1ª vez pode demorar - download de cross-compilers)")
        _ts("  Pacotes do binary cache oficial (cache.nixos.org) - sem compilação local.")
        rc = server.run("nixos-rebuild switch 2>&1", timeout=5400, sudo=True)
        if rc != 0:
            raise RuntimeError(
                f"nixos-rebuild switch falhou (exit {rc}). "
                "Verifica /etc/nixos/vaultseed.nix e os logs acima."
            )
        _ts("nixos-rebuild switch concluído.")

    def build_script(self, op: RemoteOp) -> str:
        N = 10
        sdk_cmds_str = sdk_cmds(java_home=False)
        cargo_cfg_b64 = _b64(
            "[target.aarch64-unknown-linux-gnu]\n"
            "linker = \"aarch64-unknown-linux-gnu-gcc\"\n\n"
            "[target.armv7-unknown-linux-gnueabihf]\n"
            "linker = \"armv7l-unknown-linux-gnueabihf-gcc\"\n\n"
            "[target.i686-unknown-linux-gnu]\n"
            "linker = \"i686-unknown-linux-gnu-gcc\"\n"
        )

        return (
            "#!/usr/bin/env bash\n"
            "set -u\n"
            + op.preamble() +
            "export PATH=\"/run/current-system/sw/bin"
            ":/nix/var/nix/profiles/default/bin"
            ":$HOME/.nix-profile/bin"
            ":$HOME/.cargo/bin"
            ":$PATH\"\n"
            "source /etc/profile.d/nix.sh        2>/dev/null || true\n"
            "source /etc/profile.d/nix-daemon.sh 2>/dev/null || true\n"
            "source ~/.cargo/env                 2>/dev/null || true\n"
            "export JAVA_HOME=\"${JAVA_HOME:-$(dirname $(dirname $(readlink -f $(which java) 2>/dev/null)) 2>/dev/null)}\"\n"
            "export ANDROID_SDK_ROOT=\"${ANDROID_SDK_ROOT:-$HOME/android-sdk}\"\n"
            "export ANDROID_NDK_HOME=\"${ANDROID_NDK_HOME:-$HOME/android-sdk/ndk/r27c}\"\n"
            "export XWIN_ACCEPT_LICENSE=1\n"
            "export XWIN_ARCH=\"${XWIN_ARCH:-x86,x86_64,aarch64}\"\n\n"
            f'_fase "Passo 1/{N}: Limpeza de ficheiros no formato antigo"\n'
            "shopt -s nullglob\n"
            "for f in ~/.vaultseed/*.sh ~/.vaultseed/*.log ~/.vaultseed/*.status "
            "~/.vaultseed/*.pid ~/.vaultseed/*.lock; do\n"
            "  rm -f \"$f\" && _info \"Removido (legado): $f\"\n"
            "done\n"
            "for f in ~/VaultSeed/.envrc ~/VaultSeed/flake.nix ~/VaultSeed/flake.lock; do\n"
            "  [ -f \"$f\" ] && rm -f \"$f\" && _info \"Removido (flake legado): $f\"\n"
            "done\n"
            "if [ -d ~/VaultSeed/.direnv ]; then\n"
            "  rm -rf ~/VaultSeed/.direnv && _info 'Removido: ~/VaultSeed/.direnv'\n"
            "fi\n"
            "if [ -d ~/VaultSeed_Release ]; then\n"
            "  _info 'AVISO: ~/VaultSeed_Release existe (formato antigo). Pode ser removido manualmente.'\n"
            "fi\n"
            "_ok 'Limpeza OK'\n\n"
            f'_fase "Passo 2/{N}: Rust (rustup)"\n'
            "if command -v rustup >/dev/null 2>&1; then\n"
            "  _ok \"rustup já instalado: $(rustup --version 2>/dev/null)\"\n"
            "else\n"
            "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs "
            "| sh -s -- -y --default-toolchain stable "
            "&& source ~/.cargo/env && _ok 'Rust instalado' "
            "|| _fail 'Rust: falhou'\n"
            "fi\n"
            "source ~/.cargo/env 2>/dev/null || true\n\n"
            f'_fase "Passo 3/{N}: Targets Rust"\n'
            f"({RUST_TARGETS} && _ok 'Targets instalados') || _fail 'Targets: alguns falharam'\n\n"
            f'_fase "Passo 4/{N}: Android NDK r27c"\n'
            "if [ -d \"$HOME/android-sdk/ndk/r27c\" ]; then\n"
            "  _ok 'NDK r27c já existe'\n"
            "else\n"
            "  mkdir -p $HOME/android-sdk/ndk && cd $HOME/android-sdk/ndk && "
            "curl -L https://dl.google.com/android/repository/"
            "android-ndk-r27c-linux.zip -o ndk.zip && "
            "unzip -q ndk.zip && mv android-ndk-r27c r27c && rm -f ndk.zip "
            "&& _ok 'NDK instalado' || _fail 'NDK: falhou'\n"
            "fi\n\n"
            f'_fase "Passo 5/{N}: Android SDK"\n'
            "if [ -d \"$HOME/android-sdk/platforms/android-34\" ]; then\n"
            "  _ok 'Android SDK já instalado'\n"
            "else\n"
            f"  ({sdk_cmds_str} && _ok 'Android SDK instalado') || _fail 'Android SDK: falhou'\n"
            "fi\n\n"
            f'_fase "Passo 6/{N}: Gradle {GRADLE_VERSION}"\n'
            f"GV={GRADLE_VERSION}\n"
            "if [ -d \"$HOME/gradle-$GV\" ]; then\n"
            "  _ok 'Gradle já instalado'\n"
            "else\n"
            "  (cd $HOME && curl -fsSL https://services.gradle.org/distributions/"
            "gradle-$GV-bin.zip -o gradle.zip && "
            "unzip -q gradle.zip -d $HOME && rm -f gradle.zip "
            "&& _ok 'Gradle instalado') || _fail 'Gradle: falhou'\n"
            "fi\n\n"
            f'_fase "Passo 7/{N}: cargo-ndk"\n'
            "(cargo ndk --version >/dev/null 2>&1 && _ok 'cargo-ndk já instalado') || "
            "(cargo install cargo-ndk --locked && _ok 'cargo-ndk instalado') || "
            "_fail 'cargo-ndk: falhou'\n\n"
            f'_fase "Passo 8/{N}: cargo-xwin"\n'
            "(cargo xwin --version >/dev/null 2>&1 && _ok 'cargo-xwin já instalado') || "
            "(cargo install cargo-xwin --locked && _ok 'cargo-xwin instalado') || "
            "_fail 'cargo-xwin: falhou'\n\n"
            f'_fase "Passo 9/{N}: Windows SDK prefetch"\n'
            "if [ -d \"$HOME/.xwin-cache\" ] || [ -d \"$HOME/.cargo/xwin\" ]; then\n"
            "  _ok 'Windows SDK cache já existe'\n"
            "else\n"
            f"  ({XWIN_PREFETCH} && _ok 'XWIN OK') || _fail 'XWIN prefetch: falhou (não crítico)'\n"
            "fi\n\n"
            f'_fase "Passo 10/{N}: wasm-pack (extensão de browser)"\n'
            "if command -v wasm-pack >/dev/null 2>&1; then\n"
            "  _ok \"wasm-pack já instalado: $(wasm-pack --version 2>/dev/null)\"\n"
            "else\n"
            "  (cargo install wasm-pack --locked && _ok 'wasm-pack instalado') "
            "|| _fail 'wasm-pack: falhou'\n"
            "fi\n\n"
            "_info 'A configurar ~/.cargo/config.toml …'\n"
            f"mkdir -p $HOME/.cargo && echo {cargo_cfg_b64} | base64 -d > $HOME/.cargo/config.toml\n\n"
            "_info 'A adicionar gradle ao PATH …'\n"
            "grep -q 'gradle-' ~/.bashrc 2>/dev/null || "
            "echo 'export PATH=\"$PATH:$(ls -d $HOME/gradle-*/bin 2>/dev/null | head -1)\"'"
            " >> ~/.bashrc\n\n"
            "_info '══════════════════════════════'\n"
            "_info 'SETUP NIXOS COMPLETO'\n"
            "_info '══════════════════════════════'\n"
            "echo 0 > \"$OP_STATUS\"\n"
        )

class WindowsSetupBuilder(SetupBuilder):
    _SETUP_ADMIN_BAT_LOCAL = _REPO_ROOT / "Build" / "windows" / "setup_admin.bat"
    _NDK_VERSION = "r27c"
    _NDK_ZIP = f"android-ndk-{_NDK_VERSION}-windows.zip"
    _ANDROID_CLI_ZIP = "commandlinetools-win-10406996_latest.zip"

    def __init__(self):
        self._setup_admin_bat_remote = ""

    def pre_steps(self, server: Server) -> None:
        # O .bat já não é assumido como presente no PROJECT_DIR remoto -
        # vem da fonte local (Build/windows/) e é enviado agora, antes do
        # script principal o invocar.
        from .source_sync import SourceSync

        remote_dir = f"{SourceSync(server).remote_project_dir}/Build/windows"
        server.run_checked(f'New-Item -ItemType Directory -Force -Path "{remote_dir}" | Out-Null')
        remote_bat = f"{remote_dir}/setup_admin.bat"
        server.upload(self._SETUP_ADMIN_BAT_LOCAL, remote_bat)
        self._setup_admin_bat_remote = remote_bat

    def build_script(self, op: RemoteOp) -> str:
        N = 12
        return (
            op.preamble()
            + f'_fase "Passo 1/{N}: Limpeza de ficheiros no formato antigo"\n'
            '# Limpar .ps1 antigos em $HOME/.vaultseed (formato antigo)\n'
            'Get-ChildItem -Path "$HOME/.vaultseed" -Filter "*.ps1" -ErrorAction SilentlyContinue '
            '| Where-Object { $_.Name -ne "env.ps1" } | Remove-Item -Force -ErrorAction SilentlyContinue\n'
            '# Limpar .ps1 antigos em novo path (AppData)\n'
            'Get-ChildItem -Path "$env:APPDATA/VaultSeed/.vaultseed" -Filter "*.ps1" -ErrorAction SilentlyContinue '
            '| Where-Object { $_.Name -ne "env.ps1" } | Remove-Item -Force -ErrorAction SilentlyContinue\n'
            '_ok "Limpeza OK"\n\n'

            f'_fase "Passo 2/{N}: Rust (rustup)"\n'
            'if (Get-Command rustup -ErrorAction SilentlyContinue) {\n'
            '    _ok "rustup já instalado: $(rustup --version 2>$null)"\n'
            '} else {\n'
            '    $exe = "$env:TEMP/rustup-init.exe"\n'
            '    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $exe\n'
            '    & $exe -y --default-toolchain stable | Out-Null\n'
            '    $env:Path = "$HOME/.cargo/bin;$env:Path"\n'
            '    if (Get-Command rustup -ErrorAction SilentlyContinue) { _ok "Rust instalado" } else { _fail "Rust: falhou" }\n'
            '}\n'
            '$env:Path = "$HOME/.cargo/bin;$env:Path"\n\n'

            f'_fase "Passo 3/{N}: Componentes de administrador (MSVC, Developer Mode, JDK 17)"\n'
            'function Test-SymlinkPrivilege {\n'
            '    $testDir = "$env:TEMP/vaultseed_symlink_test_$PID"\n'
            '    New-Item -ItemType Directory -Force -Path $testDir | Out-Null\n'
            '    $target = Join-Path $testDir "target.txt"\n'
            '    $link = Join-Path $testDir "link.txt"\n'
            '    Set-Content -Path $target -Value "x"\n'
            '    $ok = $false\n'
            '    try {\n'
            '        New-Item -ItemType SymbolicLink -Path $link -Target $target -ErrorAction Stop | Out-Null\n'
            '        $ok = $true\n'
            '    } catch {}\n'
            '    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue\n'
            '    return $ok\n'
            '}\n'
            '$vswhere = "C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"\n'
            '$vcPath = $null\n'
            'if (Test-Path $vswhere) {\n'
            '    $vcPath = & $vswhere -latest -products * '
            '-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 '
            '-property installationPath 2>$null\n'
            '}\n'
            '$symlinkOk = Test-SymlinkPrivilege\n'
            '$adoptium = Get-ChildItem "C:/Program Files/Eclipse Adoptium" -Filter "jdk-17*" '
            '-ErrorAction SilentlyContinue | Select-Object -First 1\n'
            'if ($vcPath -and $symlinkOk -and $adoptium) {\n'
            '    _ok "MSVC Build Tools, Developer Mode e JDK 17 já estão presentes"\n'
            '} else {\n'
            '    _info "A configurar MSVC/Developer Mode/JDK 17 em falta - vai abrir uma '
            'janela de UAC no teu ambiente de trabalho (um só pedido para os 3), aceita-a '
            '(pode demorar vários minutos)…"\n'
            f'    $adminBat = "{self._setup_admin_bat_remote}"\n'
            '    try {\n'
            '        Start-Process -FilePath "explorer.exe" -ArgumentList "`"$adminBat`""\n'
            '    } catch { _info "Não foi possível abrir o pedido de UAC: $_" }\n'
            '    $statusFile = "$env:TEMP/vaultseed_setup_admin_status.txt"\n'
            '    for ($i = 0; $i -lt 240; $i++) {\n'
            '        Start-Sleep -Seconds 10\n'
            '        if ((Test-Path $statusFile) -and '
            '(Select-String -Path $statusFile -Pattern "^DONE$" -Quiet)) { break }\n'
            '    }\n'
            '    if (Test-Path $vswhere) {\n'
            '        $vcPath = & $vswhere -latest -products * '
            '-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 '
            '-property installationPath 2>$null\n'
            '    }\n'
            '    $symlinkOk = Test-SymlinkPrivilege\n'
            '    $adoptium = Get-ChildItem "C:/Program Files/Eclipse Adoptium" -Filter "jdk-17*" '
            '-ErrorAction SilentlyContinue | Select-Object -First 1\n'
            '}\n'
            'if ($vcPath) { _ok "MSVC Build Tools: $vcPath" } '
            'else { _fail "MSVC Build Tools: falhou - corre Build/windows/setup_admin.bat '
            'como administrador (ou aceita o pedido de UAC na próxima vez)" }\n'
            'if ($symlinkOk) { _ok "Symlinks sem admin: OK" } '
            'else { _fail "Symlinks sem admin: ainda falham - corre Build/windows/setup_admin.bat '
            'como administrador e depois termina sessao/reinicia para o privilegio '
            '\'Criar links simbolicos\' ficar activo" }\n'
            'if ($adoptium) { _ok "JAVA_HOME: $($adoptium.FullName)" } '
            'else { _info "JAVA_HOME não detectado - instala o JDK 17 (ex: winget install '
            'EclipseAdoptium.Temurin.17.JDK) e corre o setup novamente para a build de APK" }\n\n'

            f'_fase "Passo 4/{N}: Targets Rust"\n'
            'rustup target add '
            'x86_64-pc-windows-msvc i686-pc-windows-msvc aarch64-pc-windows-msvc '
            'aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android '
            'wasm32-unknown-unknown wasm32-wasip1 2>$null | Out-Null\n'
            'if ($LASTEXITCODE -eq 0) { _ok "Targets instalados" } else { _fail "Targets: alguns falharam" }\n\n'

            f'_fase "Passo 5/{N}: Android NDK {self._NDK_VERSION}"\n'
            f'if (Test-Path "$HOME/android-sdk/ndk/{self._NDK_VERSION}") {{\n'
            f'    _ok "NDK {self._NDK_VERSION} já existe"\n'
            '} else {\n'
            '    try {\n'
            '        New-Item -ItemType Directory -Force -Path "$HOME/android-sdk/ndk" | Out-Null\n'
            f'        $zip = "$env:TEMP/{self._NDK_ZIP}"\n'
            f'        Invoke-WebRequest -Uri "https://dl.google.com/android/repository/{self._NDK_ZIP}" -OutFile $zip\n'
            '        Expand-Archive -LiteralPath $zip -DestinationPath "$HOME/android-sdk/ndk" -Force\n'
            f'        Move-Item "$HOME/android-sdk/ndk/android-ndk-{self._NDK_VERSION}" "$HOME/android-sdk/ndk/{self._NDK_VERSION}"\n'
            '        Remove-Item $zip -Force\n'
            '        _ok "NDK instalado"\n'
            '    } catch { _fail "NDK: falhou - $_" }\n'
            '}\n\n'

            f'_fase "Passo 6/{N}: Android SDK (platforms 34+35)"\n'
            'if (Test-Path "$HOME/android-sdk/platforms/android-34/android.jar") {\n'
            '    _ok "Android SDK já instalado"\n'
            '} else {\n'
            '    try {\n'
            '        New-Item -ItemType Directory -Force -Path "$HOME/android-sdk/cmdline-tools" | Out-Null\n'
            '        if (-not (Test-Path "$HOME/android-sdk/cmdline-tools/latest")) {\n'
            f'            $zip = "$env:TEMP/{self._ANDROID_CLI_ZIP}"\n'
            '            Invoke-WebRequest -Uri '
            f'"https://dl.google.com/android/repository/{self._ANDROID_CLI_ZIP}" -OutFile $zip\n'
            '            Expand-Archive -LiteralPath $zip -DestinationPath "$HOME/android-sdk/cmdline-tools" -Force\n'
            '            Move-Item "$HOME/android-sdk/cmdline-tools/cmdline-tools" "$HOME/android-sdk/cmdline-tools/latest"\n'
            '            Remove-Item $zip -Force\n'
            '        }\n'
            '        $sdkm = "$HOME/android-sdk/cmdline-tools/latest/bin/sdkmanager.bat"\n'
            '        $env:ANDROID_SDK_ROOT = "$HOME/android-sdk"\n'
            '        $lic = "$HOME/android-sdk/licenses"\n'
            '        New-Item -ItemType Directory -Force -Path $lic | Out-Null\n'
            '        $licenses = @{\n'
            '            "android-sdk-license" = @("24333f8a63b6825ea9c5514f83c2829b004d1fee","8933bad161af4178b1185d1a37fbf41ea5269c55","d56f5187479451eabf01fb78af6dfcb131a6481e")\n'
            '            "android-sdk-preview-license" = @("84831b9409646a918e30573bab4c9c91346d8abd")\n'
            '            "android-googletv-license" = @("601085b94cd77f0b54ff86406957099ebe79c4d")\n'
            '            "android-sdk-arm-dbt-license" = @("859f317696f67ef3d7f30a50a5560e7834b43903")\n'
            '            "google-gdk-license" = @("33b6a2b64607f11b759f320ef9dff4ae5c47d97a")\n'
            '            "mips-android-sysimage-license" = @("e9acab5b5fbb560a72cfaecce8946896ff6aab9d")\n'
            '            "intel-android-extra-license" = @("d975f751698a77b662f1254ddbeed3901e976f5")\n'
            '        }\n'
            '        $licenses.GetEnumerator() | ForEach-Object {\n'
            '            $content = ($_.Value -join "`n") + "`n"\n'
            '            Set-Content -Path "$lic/$($_.Key)" -Value $content -NoNewline -Encoding ascii\n'
            '        }\n'
            '        & $sdkm "platform-tools" "platforms;android-34" "build-tools;34.0.0" '
            '"platforms;android-35" "build-tools;35.0.0" *> $null\n'
            '        if (Test-Path "$HOME/android-sdk/platforms/android-34/android.jar") {\n'
            '            _ok "Android SDK instalado"\n'
            '        } else {\n'
            '            _fail "Android SDK: platforms/android-34/android.jar não encontrado após instalação"\n'
            '        }\n'
            '    } catch { _fail "Android SDK: falhou - $_" }\n'
            '}\n\n'

            f'_fase "Passo 7/{N}: Gradle {GRADLE_VERSION}"\n'
            f'if (Test-Path "$HOME/gradle-{GRADLE_VERSION}") {{\n'
            '    _ok "Gradle já instalado"\n'
            '} else {\n'
            '    try {\n'
            f'        $zip = "$env:TEMP/gradle-{GRADLE_VERSION}-bin.zip"\n'
            '        Invoke-WebRequest -Uri '
            f'"https://services.gradle.org/distributions/gradle-{GRADLE_VERSION}-bin.zip" -OutFile $zip\n'
            '        Expand-Archive -LiteralPath $zip -DestinationPath "$HOME" -Force\n'
            '        Remove-Item $zip -Force\n'
            '        _ok "Gradle instalado"\n'
            '    } catch { _fail "Gradle: falhou - $_" }\n'
            '}\n\n'

            f'_fase "Passo 8/{N}: cargo-ndk"\n'
            '$ndkOk = $false\n'
            'try { cargo ndk --version *> $null; $ndkOk = $? } catch {}\n'
            'if ($ndkOk) { _ok "cargo-ndk já instalado" }\n'
            'else {\n'
            '    cargo install cargo-ndk --locked *> $null\n'
            '    if ($?) { _ok "cargo-ndk instalado" } else { _fail "cargo-ndk: falhou" }\n'
            '}\n\n'

            f'_fase "Passo 9/{N}: ninja (compilação da skia, usada pelo egui/eframe)"\n'
            '$env:Path = "$env:LOCALAPPDATA/Microsoft/WinGet/Links;" + $env:Path\n'
            'if (Get-Command ninja -ErrorAction SilentlyContinue) {\n'
            '    _ok "ninja já instalado: $(ninja --version 2>$null)"\n'
            '} else {\n'
            '    winget install Ninja-build.Ninja --accept-package-agreements '
            '--accept-source-agreements --disable-interactivity *> $null\n'
            '    $env:Path = "$env:LOCALAPPDATA/Microsoft/WinGet/Links;" + $env:Path\n'
            '    if (Get-Command ninja -ErrorAction SilentlyContinue) { _ok "ninja instalado" } '
            'else { _fail "ninja: falhou - instala manualmente (winget install Ninja-build.Ninja) e garante que fica no PATH" }\n'
            '}\n\n'

            f'_fase "Passo 10/{N}: wasm-pack (extensão de browser)"\n'
            'if (Get-Command wasm-pack -ErrorAction SilentlyContinue) {\n'
            '    _ok "wasm-pack já instalado: $(wasm-pack --version 2>$null)"\n'
            '} else {\n'
            '    cargo install wasm-pack --locked *> $null\n'
            '    if ($?) { _ok "wasm-pack instalado" } else { _fail "wasm-pack: falhou" }\n'
            '}\n\n'

            f'_fase "Passo 11/{N}: LLVM 18 (libclang, necessário pelo bindgen da skia-bindings)"\n'
            'if (Test-Path "C:/LLVM18/bin/libclang.dll") {\n'
            '    _ok "LLVM 18 já instalado"\n'
            '} else {\n'
            '    $llvmExe = "$env:TEMP/LLVM-18.1.8-win64.exe"\n'
            '    Invoke-WebRequest -Uri '
            '"https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/LLVM-18.1.8-win64.exe" '
            '-OutFile $llvmExe\n'
            '    $sevenZip = "C:/Program Files/7-Zip/7z.exe"\n'
            '    if (Test-Path $sevenZip) { & $sevenZip x $llvmExe -oC:/LLVM18 -y *> $null }\n'
            '    if (Test-Path "C:/LLVM18/bin/libclang.dll") { _ok "LLVM 18 instalado" } '
            'else { _fail "LLVM: falhou - extrai manualmente LLVM-18.1.8-win64.exe para C:/LLVM18 com 7-Zip" }\n'
            '}\n\n'

            f'_fase "Passo 12/{N}: ambiente persistente ($env:APPDATA/VaultSeed/.vaultseed/env.ps1)"\n'
            '$envLines = @(\n'
            '    \'$env:ANDROID_SDK_ROOT = "$HOME/android-sdk"\'\n'
            f'    \'$env:ANDROID_NDK_HOME = "$HOME/android-sdk/ndk/{self._NDK_VERSION}"\'\n'
            '    \'$env:ANDROID_NDK = $env:ANDROID_NDK_HOME\'\n'
            '    \'$env:ANDROID_HOME = $env:ANDROID_SDK_ROOT\'\n'
            '    \'$adoptium = Get-ChildItem "C:/Program Files/Eclipse Adoptium" -Filter "jdk-17*" -ErrorAction SilentlyContinue | Select-Object -First 1\'\n'
            '    \'if ($adoptium) { $env:JAVA_HOME = $adoptium.FullName }\'\n'
            '    \'$gradleBin = Get-ChildItem "$HOME" -Filter "gradle-*" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1\'\n'
            '    \'if ($gradleBin) { $env:Path = "$($gradleBin.FullName)/bin;$env:Path" }\'\n'
            '    \'$env:Path = "$HOME/.cargo/bin;$env:Path"\'\n'
            '    \'$env:Path = "$env:LOCALAPPDATA/Microsoft/WinGet/Links;$env:Path"\'\n'
            '    \'if (Test-Path "C:/LLVM18/bin/libclang.dll") '
            '{ $env:LIBCLANG_PATH = "C:/LLVM18/bin" } '
            'elseif (Test-Path "C:/Program Files/LLVM/bin/libclang.dll") '
            '{ $env:LIBCLANG_PATH = "C:/Program Files/LLVM/bin" }\'\n'
            ')\n'
            '$vaultSeedDir = "$env:APPDATA/VaultSeed/.vaultseed"\n'
            'New-Item -ItemType Directory -Force -Path $vaultSeedDir | Out-Null\n'
            '$envLines | Set-Content "$vaultSeedDir/env.ps1"\n'
            '_ok "env.ps1 escrito em $vaultSeedDir/env.ps1"\n\n'

            '_info "══════════════════════════"\n'
            '_info "SETUP WINDOWS COMPLETO"\n'
            '_info "══════════════════════════"\n'
            'Set-Content -Path $OP_STATUS -Value 0 -NoNewline\n'
        )

class SetupJob:
    def __init__(self, server: Server, builder: SetupBuilder):
        self.server  = server
        self.builder = builder

    def run(self, op_type: str, *, timeout: int = 7200, poll: int = 20) -> int:
        with self.server as server:
            _ts(f"Conectado a {server.label}")
            self.builder.pre_steps(server)

            op = RemoteOp(server, op_type)
            op.launch(self.builder.build_script(op))
            rc = op.monitor(timeout=timeout, poll=poll)

        if rc == RC_DETACHED:
            _ts("Monitor desligado - o setup continua a correr no servidor.")
        return rc
