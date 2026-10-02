from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

class MergeSlashesOffRule(Rule):
    rule_id = "NGX-SLASH-001"
    title = "merge_slashes is disabled"
    description = (
        "Detects merge_slashes off, which passes repeated slashes "
        "through to proxied applications."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Remove merge_slashes off unless the application requires it, "
        "and confirm the proxied application is not vulnerable to path traversal."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message="merge_slashes is set to off.",
                evidence=(format_directive(directive),),
            )
            for directive in find_directives(directives, "merge_slashes")
            if directive.arguments == ("off",)
        )
