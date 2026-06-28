"""Config - única classe que lê/escreve Build/.env.
Servidores são numerados (VS_HOST_<n>, VS_USER_<n>, VS_PASS_<n>, VS_OS_<n>, VS_LOCAL_<n>).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")

@dataclass(frozen=True)
class ServerProfile:
    n: int
    host: str = ""
    user: str = ""
    password: str = ""
    os: str = "linux"
    local: bool = False

    @property
    def label(self) -> str:
        if self.local:
            return f"{self.user or '(sem user)'} (local)  [{self.os}]"
        return f"{self.user or '(sem user)'}@{self.host or '(sem host)'}  [{self.os}]"

class Config:
    def __init__(self, env_file: Path):
        self.env_file = env_file
        self._values: dict[str, str] = {}
        self.load()

    def load(self) -> None:
        self._values = {}
        if not self.env_file.exists():
            return
        for line in self.env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            self._values[key.strip()] = value.strip()

    def save(self) -> None:
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"{k}={v}" for k, v in self._values.items()]
        self.env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def get(self, key: str, default: str = "") -> str:
        return self._values.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        if key not in self._values:
            return default
        return _truthy(self._values[key])

    def get_int(self, key: str, default: int) -> int:
        try:
            return int(self._values.get(key, str(default)))
        except ValueError:
            return default

    def set(self, key: str, value: str) -> None:
        self._values[key] = value

    def set_many(self, pairs: dict[str, str]) -> None:
        self._values.update(pairs)

    def items(self):
        return self._values.items()

    @property
    def active_server_n(self) -> int:
        return self.get_int("VS_SERVER", 1)

    def set_active_server(self, n: int) -> None:
        self.set("VS_SERVER", str(n))

    def server(self, n: int | None = None) -> ServerProfile:
        n = n if n is not None else self.active_server_n
        return ServerProfile(
            n=n,
            host=self.get(f"VS_HOST_{n}"),
            user=self.get(f"VS_USER_{n}"),
            password=self.get(f"VS_PASS_{n}"),
            os=self.get(f"VS_OS_{n}", "linux").strip().lower(),
            local=self.get_bool(f"VS_LOCAL_{n}"),
        )

    def max_server_n(self) -> int:
        n = 1
        fields = ("VS_HOST", "VS_USER", "VS_PASS", "VS_OS", "VS_LOCAL")
        while any(f"{field}_{n}" in self._values for field in fields):
            n += 1
        return n - 1

    def server_keys(self, n: int) -> set[str]:
        return {f"VS_HOST_{n}", f"VS_USER_{n}", f"VS_PASS_{n}", f"VS_OS_{n}", f"VS_LOCAL_{n}"}

    def port(self) -> int:
        return self.get_int("VS_PORT", 22)

    def profile_name(self) -> str:
        return self.get("VS_PROFILE", "full")

    def timings_enabled(self) -> bool:
        return self.get_bool("VS_TIMINGS", False)

    def backtrace_value(self) -> str:
        return self.get("VS_BACKTRACE", "0")

    def build_release(self) -> bool:
        return self.get_bool("VS_BUILD_RELEASE", True)

    def fast_lto(self) -> bool:
        return self.get_bool("VS_LTO", True)

    def cargo_lto_value(self) -> str:
        return "false" if self.fast_lto() else "thin"

    def codegen_units(self) -> int:
        value = self.get_int("VS_CODEGEN_UNITS", 256)
        return value if value > 0 else 256

    def build_jobs(self) -> int | None:
        value = self.get_int("VS_BUILD_JOBS", 0)
        return value if value > 0 else None

    def slint_opt_level(self) -> str | None:
        raw = self.get("VS_SLINT_OPT_LEVEL", "").strip().strip('"').strip("'")
        if not raw:
            return None
        if raw in ("0", "1", "2", "3"):
            return raw
        if raw in ("s", "z"):
            return f'"{raw}"'
        return None
