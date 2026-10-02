from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Directive:
    name: str
    arguments: tuple[str]
    file: Path
    line: int
    children: tuple["Directive", ...] | None = None