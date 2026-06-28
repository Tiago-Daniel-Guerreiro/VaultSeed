from __future__ import annotations

import json
import random
import string
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

REPO_ROOT   = Path(__file__).resolve().parent.parent.parent
RESULT_ROOT = REPO_ROOT / "result"

def new_id(op_type: str) -> str:
    ts     = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = "".join(random.choices("0123456789abcdef", k=4))
    return f"{op_type}-{ts}-{suffix}"

def parse_type(action_id: str) -> str:
    parts = action_id.split("-")
    type_parts = []
    for p in parts:
        if p.isdigit() and len(p) == 8:
            break
        type_parts.append(p)
    return "-".join(type_parts) if type_parts else parts[0]

def stamp_from_id(action_id: str) -> str:
    parts = action_id.split("-")
    for i, p in enumerate(parts[:-1]):
        if p.isdigit() and len(p) == 8 and parts[i + 1].isdigit() and len(parts[i + 1]) == 6:
            return f"{p}_{parts[i + 1]}"
    raise ValueError(f"Não foi possível extrair stamp de '{action_id}'")

@dataclass
class Action:
    id: str
    meta: dict = field(default_factory=dict)

    @classmethod
    def create(cls, op_type: str) -> "Action":
        return cls(id=new_id(op_type))

    @classmethod
    def load(cls, action_id: str) -> "Action":
        return cls(id=action_id, meta=cls._read_meta(action_id))

    @property
    def op_type(self) -> str:
        return self.meta.get("type") or parse_type(self.id)

    @property
    def local_dir(self) -> Path:
        d = RESULT_ROOT / self.id
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def local_summary(self) -> Path:
        return self.local_dir / "summary.log"

    @staticmethod
    def _meta_path(action_id: str) -> Path:
        return RESULT_ROOT / action_id / "action.json"

    @staticmethod
    def _read_meta(action_id: str) -> dict:
        p = Action._meta_path(action_id)
        if not p.exists():
            return {"id": action_id, "status": "unknown"}
        try:
            return json.loads(p.read_text("utf-8"))
        except Exception:
            return {"id": action_id, "status": "error"}

    def save_meta(self, **fields) -> None:
        self.meta = self._read_meta(self.id)
        self.meta.update({"id": self.id, **fields})
        p = self.local_dir / "action.json"
        p.write_text(json.dumps(self.meta, indent=2, default=str), "utf-8")

    @staticmethod
    def list_recent(limit: int = 30) -> list["Action"]:
        if not RESULT_ROOT.exists():
            return []
        dirs = sorted(
            (d for d in RESULT_ROOT.iterdir() if d.is_dir()),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        return [Action.load(d.name) for d in dirs[:limit]]
