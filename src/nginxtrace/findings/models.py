from dataclasses import dataclass
from pathlib import Path

from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    remediation: str
    confidence: Confidence
    file: Path
    line: int
    evidence: tuple[str, ...] = ()
