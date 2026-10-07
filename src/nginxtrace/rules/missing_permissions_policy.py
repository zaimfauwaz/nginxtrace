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


class MissingPermissionsPolicyRule(Rule):
    rule_id = "NGX-HEADER-SEC-015"
    title = "Missing Permissions-Policy header"
    description = (
        "Detects HTTPS server blocks that do not define a Permissions-Policy "
        "header."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add a Permissions-Policy header that disables browser features the "
        "application does not need, for example: `add_header "
        "Permissions-Policy \"camera=(), microphone=(), geolocation=()\" "
        "always;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            headers = direct_headers(directive)

            if has_header(headers, "Permissions-Policy"):
                continue

            findings.append(
                self.create_finding(
                    directive,
                    message=(
                        "HTTPS server block does not define a "
                        "Permissions-Policy header."
                    ),
                    evidence=(format_directive(directive),),
                )
            )

        return tuple(findings)