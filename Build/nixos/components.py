"""Componentes desinstaláveis no NixOS"""

from ..core.component import Component

GRADLE_DIR_GLOB = "gradle-*"
NDK_VERSION = "r27c"

def components() -> list[Component]:
    return [
        Component(
            "nixos_module", "Módulo NixOS (vaultseed.nix + import em configuration.nix)",
            note="Remove /etc/nixos/vaultseed.nix, retira o import de configuration.nix "
                 "(restaura o backup .bak-vaultseed se existir) e corre "
                 "'nixos-rebuild switch' para aplicar - pode demorar vários minutos "
                 "e requer sudo (será pedido).",
        ),
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
            "cargo_config", "$HOME/.cargo/config.toml (linkers cross)",
            bash=(
                '_fase "A remover ~/.cargo/config.toml"\n'
                'rm -f "$HOME/.cargo/config.toml" && _ok "config.toml removido"\n\n'
            ),
        ),
    ]
