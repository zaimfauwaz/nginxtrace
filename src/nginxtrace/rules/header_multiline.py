from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

class MultilineHeaderRule(Rule):
    rule_id = "NGX-HEADER-ML-001"
    title = "Multi-line header value"
    description = (
        "Detects add_header values that contain a line break. Multi-line "
        "headers are deprecated by RFC 7230 and some clients reject them."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = "Put the header value on a single line."

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message="add_header contains a multi-line value.",
                evidence=(format_directive(directive).replace("\n", "\\n"),),
            )
            for directive in find_directives(directives, "add_header")
            if any("\n" in argument for argument in directive.arguments)
        )
