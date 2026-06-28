import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Erro: este script precisa do Pillow (`pip install Pillow`).", file=sys.stderr)
    sys.exit(1)

REPO_ROOT  = Path(__file__).resolve().parent.parent.parent
ICON_MAIN  = REPO_ROOT / "assets" / "icons" / "Icon.png"
ICON_SMALL = REPO_ROOT / "assets" / "icons" / "Icon-window.png"

# Pastas (percorridas recursivamente) e ficheiros individuais a regenerar.
TARGET_DIRS = [
    REPO_ROOT / "android" / "app" / "src" / "main" / "res",
    REPO_ROOT / "Wasm" / "extension" / "icons",
]
TARGET_FILES = [
    REPO_ROOT / "Wasm" / "static" / "icon.png",
]

SMALL_THRESHOLD = 48  # px - largura E altura <= isto usa o ícone pequeno

def find_images(root: Path) -> list[Path]:
    exts = {".png", ".jpg", ".jpeg", ".webp"}
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts)

def collect_targets() -> list[Path]:
    images: list[Path] = []
    for d in TARGET_DIRS:
        if d.is_dir():
            images.extend(find_images(d))
        else:
            print(f"  AVISO: pasta não encontrada, a ignorar: {d}")
    for f in TARGET_FILES:
        if f.is_file():
            images.append(f)
        else:
            print(f"  AVISO: ficheiro não encontrado, a ignorar: {f}")
    return images

def source_for(width: int, height: int) -> Path:
    return ICON_SMALL if width <= SMALL_THRESHOLD and height <= SMALL_THRESHOLD else ICON_MAIN

def main() -> None:
    if not ICON_MAIN.is_file():
        print(f"Erro: ícone principal não encontrado: {ICON_MAIN}", file=sys.stderr)
        sys.exit(1)
    if not ICON_SMALL.is_file():
        print(f"Erro: ícone pequeno não encontrado: {ICON_SMALL}", file=sys.stderr)
        sys.exit(1)

    images = collect_targets()
    if not images:
        print("Nenhuma imagem encontrada nos locais configurados.")
        return

    main_src  = Image.open(ICON_MAIN).convert("RGBA")
    small_src = Image.open(ICON_SMALL).convert("RGBA")

    pending_new: list[tuple[Path, Path]] = []  # (caminho_new, caminho_final)

    print(f"{len(images)} imagem(ns) encontrada(s):\n")

    for path in images:
        rel = path.relative_to(REPO_ROOT)
        with Image.open(path) as existing:
            width, height = existing.size

        src      = source_for(width, height)
        src_img  = small_src if src is ICON_SMALL else main_src
        resized  = src_img.resize((width, height), Image.LANCZOS)

        new_path = path.with_name(path.stem + "_new" + path.suffix)
        resized.save(new_path)

        pending_new.append((new_path, path))
        print(f"  {rel} ({width}x{height}) <- {src.name}")

    print(f"\n{len(pending_new)} imagem(ns) gerada(s) com sucesso. A substituir originais...")

    for new_path, final_path in pending_new:
        final_path.unlink()
        new_path.rename(final_path)

    print("Concluído.")

if __name__ == "__main__":
    main()