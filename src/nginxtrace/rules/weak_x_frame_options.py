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


class WeakXFrameOptionsRule(Rule):
    rule_id = "NGX-HEADER-SEC-008"
    title = "X-Frame-Options value is invalid or obsolete"
    description = (
        "Detects HTTPS server blocks that define X-Frame-Options with a "
        "value other than DENY or SAMEORIGIN."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Use `add_header X-Frame-Options DENY always;`, or use "
        "`SAMEORIGIN` when same-origin framing is required. For trusted "
        "cross-origin framing, use Content-Security-Policy frame-ancestors "
        "instead of ALLOW-FROM."
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

                if x_frame_options_value(header) is not None:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "X-Frame-Options value is invalid or obsolete; "
                            "use DENY or SAMEORIGIN."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)