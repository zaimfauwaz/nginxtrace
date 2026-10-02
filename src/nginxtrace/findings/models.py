from dataclasses import dataclass
from pathlib import Path

from nginxtrace.findings.severity import Severity

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: Path
    line: int