from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

class ValidReferersNoneRule(Rule):
    rule_id = "NGX-REFERER-001"
    title = "valid_referers allows requests without a Referer"
    description = (
        "Detects valid_referers lists that include none, which accepts "
        "requests that send no Referer header."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.MEDIUM
    remediation = (
        "Remove none from valid_referers if the check is meant to "
        "restrict access."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message="valid_referers includes none alongside other referers.",
                evidence=(format_directive(directive),),
            )
            for directive in find_directives(directives, "valid_referers")
            if len(directive.arguments) > 1 and "none" in directive.arguments
        )
