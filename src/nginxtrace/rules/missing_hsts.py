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


class MissingHstsRule(Rule):
    rule_id = "NGX-HEADER-SEC-003"
    title = "Missing Strict-Transport-Security header"
    description = (
        "Detects HTTPS server blocks that do not define a "
        "Strict-Transport-Security header."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add `add_header Strict-Transport-Security "
        "\"max-age=31536000\" always;` to the HTTPS server block."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            headers = direct_headers(directive)

            if has_header(headers, "Strict-Transport-Security"):
                continue

            findings.append(
                self.create_finding(
                    directive,
                    message=(
                        "HTTPS server block does not define a "
                        "Strict-Transport-Security header."
                    ),
                    evidence=(format_directive(directive),),
                )
            )

        return tuple(findings)