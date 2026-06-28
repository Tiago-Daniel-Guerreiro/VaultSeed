"""Component: uma parte do script (bash ou PowerShell) que desinstala uma parte que o setup instalou."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Component:
    id: str
    label: str
    bash: str = ""
    ps: str = ""
    note: str = ""
