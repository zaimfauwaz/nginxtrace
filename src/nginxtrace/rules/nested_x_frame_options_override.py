from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive
from nginxtrace.rules.security_headers import (
    direct_blocks,
    direct_headers,
    has_header,
    is_https_server,
)


class NestedXFrameOptionsOverrideRule(Rule):
    rule_id = "NGX-HEADER-SEC-009"
    title = "Nested add_header drops X-Frame-Options"
    description = (
        "Detects HTTPS server child blocks that define add_header and "
        "therefore do not inherit a parent X-Frame-Options header."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Repeat `add_header X-Frame-Options DENY always;` in the nested "
        "block, or avoid defining add_header there."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            server_headers = direct_headers(directive)

            if not has_header(server_headers, "X-Frame-Options"):
                continue

            for child in direct_blocks(directive):
                child_headers = direct_headers(child)

                if not child_headers:
                    continue

                if has_header(child_headers, "X-Frame-Options"):
                    continue

                findings.append(
                    self.create_finding(
                        child,
                        message=(
                            "Nested block defines add_header and drops inherited "
                            "X-Frame-Options."
                        ),
                        evidence=(
                            format_directive(directive),
                            format_directive(child),
                        ),
                    )
                )

        return tuple(findings)