from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive
from nginxtrace.rules.security_headers import (
    direct_headers,
    is_https_server,
    permissions_policy,
)

_BASELINE_FEATURES = frozenset(
    {
        "camera",
        "microphone",
        "geolocation",
    }
)


class PermissionsPolicyWithoutAlwaysRule(Rule):
    rule_id = "NGX-HEADER-SEC-018"
    title = "Permissions-Policy is not configured with always"
    description = (
        "Detects baseline-compliant Permissions-Policy headers on HTTPS "
        "server blocks that are not configured with the NGINX always "
        "parameter."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add the always parameter to the Permissions-Policy directive, for "
        "example: `add_header Permissions-Policy "
        "\"camera=(), microphone=(), geolocation=()\" always;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            for header in direct_headers(directive):
                if header.name != "permissions-policy":
                    continue

                policy = permissions_policy(header)

                if policy is None or not policy.is_valid:
                    continue

                if not _BASELINE_FEATURES <= policy.disabled_features:
                    continue

                if header.always:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "Permissions-Policy is not configured with the "
                            "always parameter."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)