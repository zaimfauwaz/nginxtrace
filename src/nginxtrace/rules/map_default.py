from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

class MapMissingDefaultRule(Rule):
    rule_id = "NGX-MAP-001"
    title = "map block without a default value"
    description = (
        "Detects map blocks with no default entry. Unmatched values become "
        "an empty string, which can break access-control logic."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.MEDIUM
    remediation = "Add an explicit default entry to the map block."

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message="The map block has no default entry.",
                evidence=(format_directive(directive),),
            )
            for directive in find_directives(directives, "map")
            if not any(child.name == "default" for child in directive.children or ())
        )
