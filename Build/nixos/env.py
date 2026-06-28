"""Blocos de ambiente bash para NixOS - NixOS usa o MESMO shell (bash) que Linux/Ubuntu para tudo - 
core/job.py nunca precisa de saber "é nixos" vs "é linux", só troca estas strings."""

NIX_ACTIVATE = (
    'export PATH="/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin'
    ':$HOME/.nix-profile/bin:$HOME/.cargo/bin:$PATH"\n'
    "source /etc/profile.d/nix.sh        2>/dev/null || true\n"
    "source /etc/profile.d/nix-daemon.sh 2>/dev/null || true\n"
    "source ~/.cargo/env                 2>/dev/null || true\n"
)

ANDROID_ENV = (
    "export ANDROID_NDK_HOME=$HOME/android-sdk/ndk/r27c\n"
    "export ANDROID_SDK_ROOT=$HOME/android-sdk\n"
)

_CARGO_TARGET_CACHE = (
    "export CARGO_TARGET_DIR=$HOME/.cache/vaultseed/.cargo-target\n"
    "mkdir -p \"$CARGO_TARGET_DIR\"\n"
)

CHECK_ENV = NIX_ACTIVATE + _CARGO_TARGET_CACHE
TESTS_ENV = NIX_ACTIVATE + ANDROID_ENV + _CARGO_TARGET_CACHE

NATIVE_TARGET = "x86_64-unknown-linux-gnu"

CHECK_VARIANTS = [
    ("core",      "x86_64-unknown-linux-gnu", "-p vaultseed-core"),
    ("console",   "x86_64-unknown-linux-gnu", "--no-default-features"),
    ("gui",       "x86_64-unknown-linux-gnu", "--features desktop"),
    ("extension", "wasm32-unknown-unknown",   "--no-default-features --features extension"),
]

RELEASE_ENV_SNIPPET = """\
export PATH="/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:$HOME/.nix-profile/bin:$HOME/.cargo/bin:$PATH"
source /etc/profile.d/nix.sh        2>/dev/null || true
source /etc/profile.d/nix-daemon.sh 2>/dev/null || true
source ~/.cargo/env                 2>/dev/null || true
rustup default stable               2>/dev/null || true

export PKG_CONFIG_PATH="/run/current-system/sw/lib/pkgconfig:/run/current-system/sw/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

export ANDROID_NDK_HOME="$HOME/android-sdk/ndk/r27c"
export ANDROID_NDK="$ANDROID_NDK_HOME"
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_JAR="$HOME/android-sdk/platforms/android-34/android.jar"
export ANDROID_D8_JAR="$HOME/android-sdk/build-tools/34.0.0/lib/d8.jar"
export ANDROID_BUILD_TOOLS_VERSION="34.0.0"
export PATH="$PATH:$(ls -d $HOME/gradle-*/bin 2>/dev/null | head -1)"
export PATH="$PATH:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"

export CARGO_TERM_COLOR=never
export CARGO_INCREMENTAL=1
export RUST_TEST_THREADS=1
export XWIN_ACCEPT_LICENSE=1
export XWIN_ARCH=x86,x86_64,aarch64
"""

RELEASE_ENV_PREFIX = {
    "i686-unknown-linux-gnu":
        "PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=${PKG_CONFIG_PATH_i686_unknown_linux_gnu:-}",
    "aarch64-unknown-linux-gnu":
        "PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=${PKG_CONFIG_PATH_aarch64_unknown_linux_gnu:-}",
    "armv7-unknown-linux-gnueabihf":
        "PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=${PKG_CONFIG_PATH_armv7_unknown_linux_gnueabihf:-}",
}

RELEASE_BUILD_TIMEOUT = 7200
RELEASE_APK_TIMEOUT   = 1800
RELEASE_POLL_INTERVAL = 30