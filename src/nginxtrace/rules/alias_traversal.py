from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

REGEX_MODIFIERS = {"~", "~*"}

class AliasTraversalRule(Rule):
    rule_id = "NGX-ALIAS-001"
    title = "Possible path traversal via alias"
    description = (
        "Detects a prefix location without a trailing slash whose alias "
        "ends with a slash, so /files../ maps outside the alias directory."
    )
    default_severity = Severity.HIGH
    default_confidence = Confidence.MEDIUM
    remediation = (
        "Make the location and alias trailing slashes match, for example "
        "location /files/ { alias /srv/files/; }."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for location in find_directives(directives, "location"):
            if not location.arguments or location.arguments[0] in REGEX_MODIFIERS:
                continue

            if location.arguments[-1].endswith("/"):
                continue

            for child in location.children or ():
                if child.name == "alias" and child.arguments and child.arguments[0].endswith("/"):
                    findings.append(
                        self.create_finding(
                            location,
                            message=(
                                f"location {location.arguments[-1]} has no trailing slash, "
                                f"but its alias {child.arguments[0]} does."
                            ),
                            evidence=(format_directive(location), format_directive(child)),
                        )
                    )

        return tuple(findings)
