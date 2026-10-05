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


class MissingXFrameOptionsRule(Rule):
    rule_id = "NGX-HEADER-SEC-007"
    title = "Missing X-Frame-Options header"
    description = (
        "Detects HTTPS server blocks that do not define an "
        "X-Frame-Options header."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add `add_header X-Frame-Options DENY always;` to the HTTPS server "
        "block, or use SAMEORIGIN when same-origin framing is required."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            headers = direct_headers(directive)

            if has_header(headers, "X-Frame-Options"):
                continue

            findings.append(
                self.create_finding(
                    directive,
                    message=(
                        "HTTPS server block does not define an "
                        "X-Frame-Options header."
                    ),
                    evidence=(format_directive(directive),),
                )
            )

        return tuple(findings)