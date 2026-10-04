from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive
from nginxtrace.rules.security_headers import (
    direct_headers,
    has_header,
    is_https_server,
)


class MissingNosniffRule(Rule):
    rule_id = "NGX-HEADER-SEC-001"
    title = "Missing X-Content-Type-Options: nosniff"
    description = (
        "Detects HTTPS server blocks that do not define "
        "X-Content-Type-Options: nosniff."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add `add_header X-Content-Type-Options nosniff always;` "
        "to the HTTPS server block and repeat it in nested blocks "
        "that define their own add_header directives."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server" or not is_https_server(directive):
                continue

            headers = direct_headers(directive)

            if has_header(headers, "X-Content-Type-Options", "nosniff"):
                continue

            findings.append(
                self.create_finding(
                    directive,
                    message=(
                        "HTTPS server block does not define "
                        "X-Content-Type-Options: nosniff."
                    ),
                    evidence=(format_directive(directive),),
                )
            )

        return tuple(findings)