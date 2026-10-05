from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive
from nginxtrace.rules.security_headers import (
    direct_headers,
    hsts_max_age,
    is_https_server,
)

_MIN_HSTS_MAX_AGE = 15_768_000


class HstsWithoutAlwaysRule(Rule):
    rule_id = "NGX-HEADER-SEC-006"
    title = "Strict-Transport-Security is not configured with always"
    description = (
        "Detects valid Strict-Transport-Security headers on HTTPS server "
        "blocks that are not configured with the NGINX always parameter."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add the always parameter to the Strict-Transport-Security directive, "
        "for example: `add_header Strict-Transport-Security "
        "\"max-age=31536000\" always;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            for header in direct_headers(directive):
                if header.name != "strict-transport-security":
                    continue

                max_age = hsts_max_age(header)

                if max_age is None or max_age < _MIN_HSTS_MAX_AGE:
                    continue

                if header.always:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "Strict-Transport-Security is not configured with "
                            "the always parameter."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)