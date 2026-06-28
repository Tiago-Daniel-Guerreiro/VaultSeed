"""Blocos de ambiente bash para Linux/Ubuntu"""

ANDROID_ENV = (
    "export ANDROID_NDK_HOME=$HOME/android-sdk/ndk/r27c\n"
    "export ANDROID_SDK_ROOT=$HOME/android-sdk\n"
)

_CARGO_TARGET_CACHE = (
    "export CARGO_TARGET_DIR=$HOME/.cache/vaultseed/.cargo-target\n"
    "mkdir -p \"$CARGO_TARGET_DIR\"\n"
)

CHECK_ENV = (
    "export ANDROID_NDK_HOME=$HOME/android-sdk/ndk/r27c\n"
    "export ANDROID_NDK=$ANDROID_NDK_HOME\n"
    "export ANDROID_SDK_ROOT=$HOME/android-sdk\n"
    "export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64\n"
    "source ~/.cargo/env 2>/dev/null || true\n"
    + _CARGO_TARGET_CACHE
)

TESTS_ENV = (
    "source ~/.cargo/env 2>/dev/null || true\n"
    + ANDROID_ENV
    + "export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64\n"
    + _CARGO_TARGET_CACHE
)

NATIVE_TARGET = "x86_64-unknown-linux-gnu"

CHECK_VARIANTS = [
    ("core",      "x86_64-unknown-linux-gnu", "-p vaultseed-core"),
    ("console",   "x86_64-unknown-linux-gnu", "--no-default-features"),
    ("gui",       "x86_64-unknown-linux-gnu", "--features desktop"),
    ("extension", "wasm32-unknown-unknown",   "--no-default-features --features extension"),
]

RELEASE_ENV_SNIPPET = """\
export ANDROID_NDK_HOME="$HOME/android-sdk/ndk/r27c"
export ANDROID_NDK="$ANDROID_NDK_HOME"
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_JAR="$HOME/android-sdk/platforms/android-34/android.jar"
export PATH="$PATH:$(ls -d $HOME/gradle-*/bin 2>/dev/null | head -1)"
export ANDROID_D8_JAR="$HOME/android-sdk/build-tools/34.0.0/lib/d8.jar"
export ANDROID_BUILD_TOOLS_VERSION="34.0.0"
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
export PATH="$PATH:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CARGO_TERM_COLOR=never
export CARGO_INCREMENTAL=1
export RUST_TEST_THREADS=1
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
export CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc
export CXX_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-g++
export CC_i686_unknown_linux_gnu=i686-linux-gnu-gcc
export CXX_i686_unknown_linux_gnu=i686-linux-gnu-g++
export XWIN_ACCEPT_LICENSE=1
export XWIN_ARCH=x86,x86_64,aarch64
"""

RELEASE_ENV_PREFIX = {
    "i686-unknown-linux-gnu":
        "PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=/usr/lib/i386-linux-gnu/pkgconfig",
    "aarch64-unknown-linux-gnu":
        "PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig",
    "armv7-unknown-linux-gnueabihf":
        "PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=/usr/lib/arm-linux-gnueabihf/pkgconfig",
}

RELEASE_BUILD_TIMEOUT = 7200
RELEASE_APK_TIMEOUT   = 1800
RELEASE_POLL_INTERVAL = 30