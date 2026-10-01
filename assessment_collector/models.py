from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Credentials:
    domain: str
    username: str
    password: str = field(repr=False)

    @property
    def principal(self) -> str:
        return f"{self.domain}\\{self.username}" if self.domain else self.username


@dataclass(slots=True)
class ModuleResult:
    success: bool
    reason: str = ""
    targets: dict[str, str] = field(default_factory=dict)
    details: dict[str, object] = field(default_factory=dict)
    files: list[Path] = field(default_factory=list)
