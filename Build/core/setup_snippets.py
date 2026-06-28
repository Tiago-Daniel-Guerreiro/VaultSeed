"""Snippets bash partilhados pelos scripts de setup (linux e nixos)"""
GRADLE_VERSION = "8.10.2"

RUST_TARGETS = (
    "rustup target add "
    "x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu "
    "armv7-unknown-linux-gnueabihf i686-unknown-linux-gnu "
    "aarch64-linux-android armv7-linux-androideabi "
    "x86_64-linux-android i686-linux-android "
    "wasm32-unknown-unknown wasm32-wasip1 "
    "x86_64-pc-windows-msvc i686-pc-windows-msvc aarch64-pc-windows-msvc"
)

XWIN_PREFETCH = (
    "export XWIN_ACCEPT_LICENSE=1 XWIN_ARCH=x86,x86_64,aarch64 && "
    "D=$(mktemp -d) && cd \"$D\" && cargo new --bin xwin_probe -q && "
    "cd xwin_probe && "
    "cargo xwin build --release --target x86_64-pc-windows-msvc && "
    "cargo xwin build --release --target i686-pc-windows-msvc && "
    "cargo xwin build --release --target aarch64-pc-windows-msvc && "
    "cd / && rm -rf \"$D\" && echo 'Windows SDK OK'"
)

def sdk_cmds(java_home: bool = False) -> str:
    """Instalação do Android SDK (cmdline-tools + platforms 34/35).
    `java_home=True` exporta JAVA_HOME (necessário no Ubuntu); no NixOS vem do sistema."""
    java = "export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 && " if java_home else ""
    return (
        "export ANDROID_SDK_ROOT=$HOME/android-sdk && "
        + java +
        "mkdir -p $ANDROID_SDK_ROOT/cmdline-tools && "
        "cd $ANDROID_SDK_ROOT/cmdline-tools && "
        "([ -d latest ] || ("
        "curl -L https://dl.google.com/android/repository/"
        "commandlinetools-linux-10406996_latest.zip -o cli.zip && "
        "unzip -q cli.zip && mkdir -p latest && "
        "mv cmdline-tools/* latest/ && rm -rf cmdline-tools cli.zip)) && "
        "SDKM=$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager && "
        "yes | $SDKM --licenses >/dev/null 2>&1 || true && "
        "$SDKM 'platform-tools' "
        "'platforms;android-34' 'build-tools;34.0.0' "
        "'platforms;android-35' 'build-tools;35.0.0'"
    )
