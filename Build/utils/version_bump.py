import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CARGO_TOMLS = [
    REPO_ROOT / "Cargo.toml",
    REPO_ROOT / "Core" / "Cargo.toml",
    REPO_ROOT / "Gui" / "Cargo.toml",
    REPO_ROOT / "Slint" / "Cargo.toml",
    REPO_ROOT / "Console" / "Cargo.toml",
]
CARGO_LOCK    = REPO_ROOT / "Cargo.lock"
WASM_MANIFEST = REPO_ROOT / "Wasm" / "extension" / "manifest.json"
ANDROID_GRADLE = REPO_ROOT / "android" / "app" / "build.gradle"

CARGO_PACKAGE_NAMES = {"vaultseed", "vaultseed-core", "vaultseed-gui", "vaultseed-slint", "vaultseed-console"}

VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)

def read_current_version() -> str:
    text = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = VERSION_RE.search(text)
    if not m:
        print("Erro: não encontrei \"version = ...\" em Cargo.toml.", file=sys.stderr)
        sys.exit(1)
    return m.group(1)

def validate_version(version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"Erro: \"{version}\" não parece uma versão semver válida (ex: 0.5.2).", file=sys.stderr)
        sys.exit(1)

def update_cargo_toml(path: Path, new_version: str) -> bool:
    text = path.read_text(encoding="utf-8")
    new_text, count = VERSION_RE.subn(f'version = "{new_version}"', text, count=1)
    if count == 0:
        print(f"  AVISO: nenhum \"version = ...\" encontrado em {path.relative_to(REPO_ROOT)}")
        return False
    path.write_text(new_text, encoding="utf-8")
    return True

def update_cargo_lock(path: Path, new_version: str) -> int:
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    updated = 0
    pending_name: str | None = None

    for i, line in enumerate(lines):
        m_name = re.match(r'^name = "([^"]+)"', line)
        if m_name:
            pending_name = m_name.group(1)
            continue

        m_version = re.match(r'^version = "([^"]+)"', line)
        if m_version and pending_name in CARGO_PACKAGE_NAMES:
            lines[i] = f'version = "{new_version}"'
            updated += 1
            pending_name = None

    if updated:
        path.write_text("\n".join(lines), encoding="utf-8")
    return updated

def update_wasm_manifest(path: Path, new_version: str) -> bool:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "version" not in data:
        return False
    data["version"] = new_version
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True

def update_android_gradle(path: Path, new_version: str) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8")

    m_code = re.search(r"versionCode\s+(\d+)", text)
    if not m_code:
        print(f"  AVISO: versionCode não encontrado em {path.relative_to(REPO_ROOT)}")
        return (0, 0)
    old_code = int(m_code.group(1))
    new_code = old_code + 1

    text = re.sub(r"versionCode\s+\d+", f"versionCode {new_code}", text, count=1)
    text = re.sub(r"versionName\s+'[^']*'", f"versionName '{new_version}'", text, count=1)

    path.write_text(text, encoding="utf-8")
    return (old_code, new_code)

def main() -> None:
    current = read_current_version()
    print(f"Versão actual: {current}")

    new_version = input("Nova versão (ex: 0.5.2): ").strip()
    if not new_version:
        print("Cancelado (nada introduzido).")
        return
    validate_version(new_version)

    if new_version == current:
        print("A nova versão é igual à actual - nada a fazer.")
        return

    print(f"\nA mudar {current} -> {new_version}...\n")

    for toml_path in CARGO_TOMLS:
        if update_cargo_toml(toml_path, new_version):
            print(f"  OK  {toml_path.relative_to(REPO_ROOT)}")

    if CARGO_LOCK.is_file():
        n = update_cargo_lock(CARGO_LOCK, new_version)
        print(f"  OK  Cargo.lock ({n} entrada(s) vaultseed-*)")

    if WASM_MANIFEST.is_file():
        if update_wasm_manifest(WASM_MANIFEST, new_version):
            print(f"  OK  {WASM_MANIFEST.relative_to(REPO_ROOT)}")

    if ANDROID_GRADLE.is_file():
        old_code, new_code = update_android_gradle(ANDROID_GRADLE, new_version)
        if new_code:
            print(f"  OK  {ANDROID_GRADLE.relative_to(REPO_ROOT)} (versionCode {old_code} -> {new_code})")

    print("\nConcluído.")

if __name__ == "__main__":
    main()