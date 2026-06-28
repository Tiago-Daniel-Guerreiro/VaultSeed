"""Blocos de ambiente PowerShell para Windows"""

_CARGO_HOME_SHORT = (
    '$env:Path = "$env:LOCALAPPDATA\\Microsoft\\WinGet\\Links;" + $env:Path\n'
    'if (Test-Path "C:\\LLVM18\\bin\\libclang.dll") '
    '{ $env:LIBCLANG_PATH = "C:\\LLVM18\\bin" } '
    'elseif (Test-Path "C:\\Program Files\\LLVM\\bin\\libclang.dll") '
    '{ $env:LIBCLANG_PATH = "C:\\Program Files\\LLVM\\bin" }\n'
    '$env:BINDGEN_EXTRA_CLANG_ARGS = '
    '"-fno-delayed-template-parsing -fno-ms-compatibility -fno-ms-extensions"\n'
)

_CARGO_TARGET_SHARED = (
    '$cacheDir = "$env:APPDATA\\VaultSeed\\cache\\.cargo-target"\n'
    'New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null\n'
    '$env:CARGO_TARGET_DIR = $cacheDir\n'
)

_SKIA_ARMV7_PATCH = (
    '$skiaSrc = Get-ChildItem "$env:CARGO_HOME/registry/src/*/skia-bindings-0.90.0" '
    '-Directory -ErrorAction SilentlyContinue | Select-Object -First 1\n'
    '$resourceDir = $null\n'
    'if ($env:LIBCLANG_PATH) {\n'
    '    $resourceDir = Get-ChildItem "$env:LIBCLANG_PATH/../lib/clang" -Directory '
    '-ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.FullName }\n'
    '}\n'
    'if ($skiaSrc -and $resourceDir) {\n'
    '    $patchDir = "$env:CARGO_HOME/skia-bindings-armv7-patch"\n'
    '    $androidRs = "$patchDir/build_support/platform/android.rs"\n'
    '    if (-not (Test-Path $androidRs)) {\n'
    '        New-Item -ItemType Directory -Force -Path $patchDir | Out-Null\n'
    '        foreach ($item in @("Cargo.toml","Cargo.lock","build.rs","build_support.rs",'
    '"README.md","src","tests","build_support")) {\n'
    '            Copy-Item "$($skiaSrc.FullName)/$item" "$patchDir/$item" '
    '-Recurse -Force -ErrorAction SilentlyContinue\n'
    '        }\n'
    '        if (-not (Test-Path "$patchDir/skia")) {\n'
    '            cmd /c mklink /J "$($patchDir -replace \'/\',\'\\\')\\skia" '
    '"$($skiaSrc.FullName -replace \'/\',\'\\\')\\skia" *> $null\n'
    '        }\n'
    '        $resourceDirFwd = $resourceDir -replace \'\\\\\',\'/\'\n'
    '        $out = New-Object System.Collections.Generic.List[string]\n'
    '        foreach ($line in (Get-Content $androidRs)) {\n'
    '            if ($line -match \'args\\.extend\\(extra_skia_cflags\\(\\)\\);\') {\n'
    '                $out.Add("    args.push(format!(`"-resource-dir=$resourceDirFwd`"));")\n'
    '            }\n'
    '            $out.Add($line)\n'
    '        }\n'
    '        $out | Set-Content $androidRs\n'
    '    }\n'
    '    $cargoToml = "$env:APPDATA/VaultSeed/source/Cargo.toml"\n'
    '    if ((Test-Path $cargoToml) -and '
    '-not (Select-String -Path $cargoToml -Pattern \'skia-bindings-armv7-patch\' -Quiet)) {\n'
    '        $patchDirFwd = $patchDir -replace \'\\\\\',\'/\'\n'
    '        Add-Content -Path $cargoToml '
    '-Value "`n[patch.crates-io]`nskia-bindings = { path = `"$patchDirFwd`" }"\n'
    '    }\n'
    '}\n'
)

_JAVA_ENV = (
    '$adoptium = Get-ChildItem "C:/Program Files/Eclipse Adoptium" -Filter "jdk-17*" '
    '-ErrorAction SilentlyContinue | Select-Object -First 1\n'
    'if ($adoptium) { $env:JAVA_HOME = $adoptium.FullName }\n'
)

ANDROID_ENV = (
    '$env:ANDROID_NDK_HOME = "$HOME\\android-sdk\\ndk\\r27c"\n'
    '$env:ANDROID_NDK = $env:ANDROID_NDK_HOME\n'
    '$env:ANDROID_SDK_ROOT = "$HOME\\android-sdk"\n'
    '$env:ANDROID_HOME = $env:ANDROID_SDK_ROOT\n'
    + _JAVA_ENV
)

CHECK_ENV = (
    '$env:ANDROID_NDK_HOME = "$HOME\\android-sdk\\ndk\\r27c"\n'
    '$env:ANDROID_NDK = $env:ANDROID_NDK_HOME\n'
    '$env:ANDROID_SDK_ROOT = "$HOME\\android-sdk"\n'
    '$env:ANDROID_HOME = $env:ANDROID_SDK_ROOT\n'
    '$env:Path = "$HOME\\.cargo\\bin;" + $env:Path\n'
    + _JAVA_ENV
    + _CARGO_HOME_SHORT
    + _CARGO_TARGET_SHARED
)

TESTS_ENV = (
    '$env:Path = "$HOME\\.cargo\\bin;" + $env:Path\n'
    + ANDROID_ENV
    + _CARGO_HOME_SHORT
    + _SKIA_ARMV7_PATCH
    + _CARGO_TARGET_SHARED
)

NATIVE_TARGET = "x86_64-pc-windows-msvc"

CHECK_VARIANTS = [
    ("core",      "x86_64-pc-windows-msvc",   "-p vaultseed-core"),
    ("console",   "x86_64-pc-windows-msvc",   "--no-default-features"),
    ("gui",       "x86_64-pc-windows-msvc",   "--features desktop"),
    ("extension", "wasm32-unknown-unknown",   "--no-default-features --features extension"),
]

RELEASE_ENV_SNIPPET = (
    """\
if (Test-Path "$env:APPDATA/VaultSeed/.vaultseed/env.ps1") { . "$env:APPDATA/VaultSeed/.vaultseed/env.ps1" }
$env:CARGO_TERM_COLOR = "never"
$env:CARGO_INCREMENTAL = "1"
$env:RUST_TEST_THREADS = "1"
"""
    + ANDROID_ENV
    + _CARGO_HOME_SHORT
    + _SKIA_ARMV7_PATCH
    + _CARGO_TARGET_SHARED
)

RELEASE_BUILD_TIMEOUT = 7200
RELEASE_APK_TIMEOUT   = 1800
RELEASE_POLL_INTERVAL = 30