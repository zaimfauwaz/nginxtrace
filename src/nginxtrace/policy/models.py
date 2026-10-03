from dataclasses import dataclass, field

from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity

@dataclass(frozen=True)
class Suppression:
    rule_id: str
    file: str
    reason: str
    line: int | None = None

    def matches(self, finding: Finding) -> bool:
        return (
            finding.rule_id == self.rule_id
            and finding.file.as_posix() == self.file
            and (self.line is None or finding.line == self.line)
        )

@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    suppression: Suppression

@dataclass(frozen=True)
class Policy:
    min_severity: Severity | None = None
    disabled_rules: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    suppressions: tuple[Suppression, ...] = ()
