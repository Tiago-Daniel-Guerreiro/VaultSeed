"""Target/TargetRegistry/ProfileStore - que targets existem, como se agrupam e que perfis os compilam."""

from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

GROUP_LINUX   = "linux"
GROUP_WINDOWS = "windows"
GROUP_ANDROID = "android"
GROUP_WASM    = "wasm"

ALL_GROUPS = (GROUP_LINUX, GROUP_WINDOWS, GROUP_ANDROID, GROUP_WASM)

# Grupos cujos targets podem ser compilados nativamente num host Windows (cargo build em vez de cargo xwin build).
WINDOWS_NATIVE_GROUPS = (GROUP_WINDOWS, GROUP_ANDROID, GROUP_WASM)

@dataclass(frozen=True)
class Target:
    triple: str
    group: str | None
    base_cmd: str
    android_abi: str | None = None
    check_cmd: str | None = None
    timings: bool = True

    def native_windows_cmd(self) -> str:
        """`base_cmd` convertido de `cargo xwin build` para `cargo build` - para compilar nativamente num host Windows em vez de cross-compile."""
        return self.base_cmd.replace("cargo xwin build", "cargo build")

@dataclass(frozen=True)
class GroupArtifact:
    art_subdir: str
    binary_name: str
    artifact_name: Callable[[str], str]

class TargetRegistry:
    """Todos os targets conhecidos e os seus grupos de artefactos."""
    def __init__(self):
        self.groups: "OrderedDict[str, GroupArtifact]" = OrderedDict([
            (GROUP_LINUX, GroupArtifact(
                art_subdir="linux", binary_name="VaultSeed",
                artifact_name=lambda t: f"VaultSeed-{t}")),
            (GROUP_WINDOWS, GroupArtifact(
                art_subdir="windows", binary_name="VaultSeed.exe",
                artifact_name=lambda t: f"VaultSeed-{t}.exe")),
            (GROUP_ANDROID, GroupArtifact(
                art_subdir="android", binary_name="libvaultseed.so",
                artifact_name=lambda t: f"libvaultseed-{t}.so")),
            (GROUP_WASM, GroupArtifact(
                art_subdir="wasm", binary_name="vaultseed.wasm",
                artifact_name=lambda t: f"vaultseed-{t}.wasm")),
        ])

        self.targets: "OrderedDict[str, Target]" = OrderedDict([
            ("wasm32-unknown-unknown", Target(
                "wasm32-unknown-unknown", GROUP_WASM,
                "cargo build --release --target wasm32-unknown-unknown "
                "--lib --no-default-features")),

            ("wasm32-wasip1", Target(
                "wasm32-wasip1", GROUP_WASM,
                "cargo build --release --target wasm32-wasip1 "
                "--lib --no-default-features")),

            ("wasm32-extension", Target(
                "wasm32-extension", None,
                "wasm-pack build --target web --release --out-dir Wasm/extension/pkg "
                "--no-default-features --features extension",
                check_cmd="cargo check --release --target wasm32-unknown-unknown "
                          "--no-default-features --features extension",
                timings=False)),

            ("x86_64-pc-windows-msvc", Target(
                "x86_64-pc-windows-msvc", GROUP_WINDOWS,
                "cargo xwin build --release --target x86_64-pc-windows-msvc "
                "--features desktop")),

            ("i686-pc-windows-msvc", Target(
                "i686-pc-windows-msvc", GROUP_WINDOWS,
                "cargo xwin build --release --target i686-pc-windows-msvc "
                "--features desktop")),

            ("aarch64-pc-windows-msvc", Target(
                "aarch64-pc-windows-msvc", GROUP_WINDOWS,
                "cargo xwin build --release --target aarch64-pc-windows-msvc "
                "--features desktop")),

            ("x86_64-unknown-linux-gnu", Target(
                "x86_64-unknown-linux-gnu", GROUP_LINUX,
                "cargo build --release --target x86_64-unknown-linux-gnu "
                "--features desktop")),

            ("i686-unknown-linux-gnu", Target(
                "i686-unknown-linux-gnu", GROUP_LINUX,
                "cargo build --release --target i686-unknown-linux-gnu "
                "--features desktop")),

            ("aarch64-unknown-linux-gnu", Target(
                "aarch64-unknown-linux-gnu", GROUP_LINUX,
                "cargo build --release --target aarch64-unknown-linux-gnu "
                "--features desktop")),

            ("armv7-unknown-linux-gnueabihf", Target(
                "armv7-unknown-linux-gnueabihf", GROUP_LINUX,
                "cargo build --release --target armv7-unknown-linux-gnueabihf "
                "--features desktop")),

            ("aarch64-linux-android", Target(
                "aarch64-linux-android", GROUP_ANDROID,
                "cargo ndk --platform 34 --target aarch64-linux-android -- "
                "build --release --features android",
                android_abi="arm64-v8a")),

            ("armv7-linux-androideabi", Target(
                "armv7-linux-androideabi", GROUP_ANDROID,
                "cargo ndk --platform 34 --target armv7-linux-androideabi -- "
                "build --release --features android",
                android_abi="armeabi-v7a")),

            ("x86_64-linux-android", Target(
                "x86_64-linux-android", GROUP_ANDROID,
                "cargo ndk --platform 34 --target x86_64-linux-android -- "
                "build --release --features android",
                android_abi="x86_64")),

            ("i686-linux-android", Target(
                "i686-linux-android", GROUP_ANDROID,
                "cargo ndk --platform 34 --target i686-linux-android -- "
                "build --release --features android",
                android_abi="x86")),
        ])

    @property
    def names(self) -> list[str]:
        return list(self.targets.keys())

    def get(self, triple: str) -> Target:
        return self.targets[triple]

    def group_lists(self, triples: list[str]) -> dict:
        """Agrupa `triples` pelos seus grupos (linux/windows/android/wasm) + mapeamento de ABIs Android (`out["android_abi"]`)."""
        out: dict = {g: [] for g in ALL_GROUPS}
        android_abi: "OrderedDict[str, str]" = OrderedDict()
        for triple in triples:
            t = self.targets[triple]
            if t.group is None:
                continue
            out[t.group].append(triple)
            if t.group == GROUP_ANDROID and t.android_abi:
                android_abi[triple] = t.android_abi
        out["android_abi"] = android_abi
        return out

    def windows_native_triples(self, triples: list[str]) -> list[str]:
        """Filtra `triples` para os que podem compilar num host Windows nativo."""
        return [
            t for t in triples
            if self.targets[t].group in WINDOWS_NATIVE_GROUPS or t == "wasm32-extension"
        ]

class ProfileStore:
    """Perfis de compilação (conjuntos nomeados de targets)"""
    BUILTIN: "OrderedDict[str, list]" = OrderedDict([
        ("full", None),  # resolvido em runtime para todos os targets
        ("release", [
            "x86_64-unknown-linux-gnu",
            "aarch64-linux-android",
            "x86_64-pc-windows-msvc",
            "wasm32-extension",
        ]),
        ("simple", [
            "x86_64-pc-windows-msvc",
        ]),
    ])

    DEFAULT_PROFILE = "full"

    def __init__(self, registry: TargetRegistry, profiles_json: Path):
        self.registry = registry
        self.profiles_json = profiles_json

    def builtin(self) -> "OrderedDict[str, list]":
        out = OrderedDict()
        for name, triples in self.BUILTIN.items():
            out[name] = triples if triples is not None else self.registry.names
        return out

    def load_custom(self) -> "OrderedDict[str, list]":
        if not self.profiles_json.exists():
            return OrderedDict()
        try:
            raw = json.loads(self.profiles_json.read_text("utf-8"))
        except Exception:
            return OrderedDict()
        out: "OrderedDict[str, list]" = OrderedDict()
        for name, triples in raw.items():
            valid = [t for t in triples if t in self.registry.targets]
            if valid:
                out[name] = valid
        return out

    def save_custom(self, custom: dict) -> None:
        self.profiles_json.write_text(
            json.dumps(custom, indent=2, ensure_ascii=False) + "\n", "utf-8"
        )

    def effective(self) -> "OrderedDict[str, list]":
        profiles = self.builtin()
        for name, triples in self.load_custom().items():
            profiles[name] = triples
        return profiles

    def active(self, profile_name: str) -> str:
        profiles = self.effective()
        name = profile_name.strip().lower()
        if name in profiles:
            return name
        return self.DEFAULT_PROFILE if self.DEFAULT_PROFILE in profiles else next(iter(profiles))

    def triples_for(self, profile_name: str) -> list[str]:
        return self.effective()[self.active(profile_name)]

    def next(self, current: str) -> str:
        names = list(self.effective().keys())
        try:
            idx = names.index(current)
        except ValueError:
            return names[0] if names else self.DEFAULT_PROFILE
        return names[(idx + 1) % len(names)]
