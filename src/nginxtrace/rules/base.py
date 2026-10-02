from abc import ABC, abstractmethod

from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity

class Rule(ABC):
    rule_id: str
    title: str
    description: str
    default_severity: Severity
    default_confidence: Confidence
    remediation: str

    @abstractmethod
    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        """Inspect parsed directives and return any findings."""

    def create_finding(
            self,
            directive: Directive,
            message: str,
            evidence: tuple[str, ...] = (),
    ) -> Finding:
        """Build a finding that reuses this rule's metadata."""
        return Finding(
            rule_id=self.rule_id,
            severity=self.default_severity,
            title=self.title,
            message=message,
            remediation=self.remediation,
            confidence=self.default_confidence,
            file=directive.file,
            line=directive.line,
            evidence=evidence,
        )
