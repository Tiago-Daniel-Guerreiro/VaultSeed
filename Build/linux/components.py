"""Componentes desinstaláveis no Linux/Ubuntu"""

from ..core.component import Component

GRADLE_DIR_GLOB = "gradle-*"
NDK_VERSION = "r27c"

_CROSS_TOOLCHAINS = " ".join([
    "gcc-aarch64-linux-gnu", "g++-aarch64-linux-gnu",
    "gcc-arm-linux-gnueabihf", "g++-arm-linux-gnueabihf",
    "gcc-i686-linux-gnu", "g++-i686-linux-gnu",
])

_FOREIGN_ARCHS = ["arm64", "armhf", "i386"]

_MULTIARCH_LIBS_BASE = [
    "libssl-dev", "libfontconfig1-dev", "libfreetype-dev",
    "libxcb-shape0-dev", "libxcb-xfixes0-dev", "libxcb-render0-dev",
    "libxkbcommon-dev", "libegl1-mesa-dev", "libwayland-dev",
    "libgles2-mesa-dev", "libgtk-3-dev",
]

_APT_BASE_DEPS = " ".join([
    "build-essential", "pkg-config", "libssl-dev", "libfontconfig1-dev",
    "libxcb-shape0-dev", "libxcb-xfixes0-dev",
    "libxkbcommon-dev", "libegl1-mesa-dev", "libwayland-dev",
    "libgles2-mesa-dev", "libgtk-3-dev", "clang", "openjdk-17-jdk",
    "ninja-build", "lld", "llvm", "mold",
])

def components() -> list[Component]:
    multiarch_libs = " ".join(
        f"{pkg}:{arch}" for arch in _FOREIGN_ARCHS for pkg in _MULTIARCH_LIBS_BASE
    )
    foreign_archs_str = " ".join(_FOREIGN_ARCHS)

    return [
        Component(
            "rust", "Rust (rustup, toolchains, targets, cargo-ndk/cargo-xwin/wasm-pack)",
            bash=(
                '_fase "A desinstalar Rust (rustup)"\n'
                'if command -v rustup >/dev/null 2>&1; then\n'
                '  source ~/.cargo/env 2>/dev/null || true\n'
                '  rustup self uninstall -y >/dev/null 2>&1 '
                '&& _ok "rustup desinstalado (~/.cargo, ~/.rustup removidos)" '
                '|| _fail "rustup self uninstall falhou"\n'
                'else\n'
                '  _ok "rustup não estava instalado"\n'
                'fi\n\n'
            ),
        ),
        Component(
            "ndk", f"Android NDK {NDK_VERSION}",
            bash=(
                f'_fase "A remover Android NDK {NDK_VERSION}"\n'
                f'rm -rf "$HOME/android-sdk/ndk/{NDK_VERSION}" '
                f'&& _ok "NDK {NDK_VERSION} removido" || _fail "NDK: falhou"\n\n'
            ),
        ),
        Component(
            "android_sdk", "Android SDK (cmdline-tools, platforms, build-tools, licenses)",
            bash=(
                '_fase "A remover Android SDK"\n'
                'rm -rf "$HOME/android-sdk/cmdline-tools" "$HOME/android-sdk/platforms" '
                '"$HOME/android-sdk/build-tools" "$HOME/android-sdk/platform-tools" '
                '"$HOME/android-sdk/licenses"\n'
                'rmdir "$HOME/android-sdk" 2>/dev/null || true\n'
                '_ok "Android SDK removido"\n\n'
            ),
        ),
        Component(
            "gradle", f"Gradle ({GRADLE_DIR_GLOB})",
            bash=(
                '_fase "A remover Gradle"\n'
                f'rm -rf "$HOME"/{GRADLE_DIR_GLOB}\n'
                'sed -i "/gradle-/d" "$HOME/.bashrc" 2>/dev/null || true\n'
                '_ok "Gradle removido"\n\n'
            ),
        ),
        Component(
            "xwin_cache", "Cache do Windows SDK (cargo-xwin)",
            bash=(
                '_fase "A remover cache do Windows SDK (xwin)"\n'
                'rm -rf "$HOME/.xwin-cache" "$HOME/.cargo/xwin" '
                '&& _ok "Cache xwin removida"\n\n'
            ),
        ),
        Component(
            "cross_toolchains", f"Cross-toolchains ({_CROSS_TOOLCHAINS})",
            bash=(
                '_fase "A remover cross-toolchains"\n'
                f'_sudo "DEBIAN_FRONTEND=noninteractive apt-get remove -y {_CROSS_TOOLCHAINS}" '
                '&& _ok "Cross-toolchains removidos" || _fail "Cross-toolchains: falhou"\n\n'
            ),
        ),
        Component(
            "multiarch", "Repositórios e libs multiarch (arm64/armhf/i386)",
            note="Remove os repositórios apt multiarch e as arquitecturas estrangeiras "
                 "(dpkg --remove-architecture). Pode afetar outros pacotes que dependam delas.",
            bash=(
                '_fase "A remover libs e repositórios multiarch"\n'
                f'_sudo "DEBIAN_FRONTEND=noninteractive apt-get remove -y {multiarch_libs}" '
                '|| _info "Algumas libs multiarch não estavam instaladas"\n'
                f'for a in {foreign_archs_str}; do '
                '_sudo "dpkg --remove-architecture $a" 2>/dev/null || true; done\n'
                '_sudo "rm -f /etc/apt/sources.list.d/ubuntu.sources '
                '/etc/apt/sources.list.d/ubuntu-ports.sources"\n'
                '_sudo "DEBIAN_FRONTEND=noninteractive apt-get update -qq" '
                '&& _ok "Multiarch removido" || _fail "Multiarch: apt-get update falhou"\n\n'
            ),
        ),
        Component(
            "base_deps", f"Dependências base + Java 17 ({_APT_BASE_DEPS})",
            note="Remove pacotes de sistema partilhados (compiladores, bibliotecas GUI, "
                 "Java 17). Só apaga se tiveres a certeza que mais nada na máquina depende deles.",
            bash=(
                '_fase "A remover dependências base + Java 17"\n'
                f'_sudo "DEBIAN_FRONTEND=noninteractive apt-get remove -y {_APT_BASE_DEPS}" '
                '&& _ok "Dependências base removidas" || _fail "Dependências base: falhou"\n\n'
            ),
        ),
        Component(
            "cargo_config", "$HOME/.cargo/config.toml (linkers cross)",
            bash=(
                '_fase "A remover ~/.cargo/config.toml"\n'
                'rm -f "$HOME/.cargo/config.toml" && _ok "config.toml removido"\n\n'
            ),
        ),
    ]
