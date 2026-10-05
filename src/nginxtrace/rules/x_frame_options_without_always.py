from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive
from nginxtrace.rules.security_headers import (
    direct_headers,
    is_https_server,
    x_frame_options_value,
)


class XFrameOptionsWithoutAlwaysRule(Rule):
    rule_id = "NGX-HEADER-SEC-010"
    title = "X-Frame-Options is not configured with always"
    description = (
        "Detects valid X-Frame-Options headers on HTTPS server blocks that "
        "are not configured with the NGINX always parameter."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add the always parameter to the X-Frame-Options directive, for "
        "example: `add_header X-Frame-Options DENY always;`. Use SAMEORIGIN "
        "instead when same-origin framing is required."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            for header in direct_headers(directive):
                if header.name != "x-frame-options":
                    continue

                if x_frame_options_value(header) is None:
                    continue

                if header.always:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "X-Frame-Options is not configured with the "
                            "always parameter."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)