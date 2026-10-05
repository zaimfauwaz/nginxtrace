from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive
from nginxtrace.rules.security_headers import (
    direct_headers,
    has_header,
    hsts_max_age,
    is_https_server,
)

_MIN_HSTS_MAX_AGE = 15_768_000


class WeakHstsRule(Rule):
    rule_id = "NGX-HEADER-SEC-004"
    title = "Strict-Transport-Security max-age is invalid or too short"
    description = (
        "Detects HTTPS server blocks whose Strict-Transport-Security header "
        "has no valid max-age or uses a max-age shorter than 180 days."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Set Strict-Transport-Security with max-age of at least 15768000 "
        "seconds, for example: `add_header Strict-Transport-Security "
        "\"max-age=31536000\" always;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            headers = direct_headers(directive)

            if not has_header(headers, "Strict-Transport-Security"):
                continue

            for header in headers:
                if header.name != "strict-transport-security":
                    continue

                max_age = hsts_max_age(header)

                if max_age is not None and max_age >= _MIN_HSTS_MAX_AGE:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "Strict-Transport-Security max-age is invalid or "
                            "shorter than 15768000 seconds."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)