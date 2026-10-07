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

_BASELINE_FEATURES = (
    "camera",
    "microphone",
    "geolocation",
)


class WeakPermissionsPolicyRule(Rule):
    rule_id = "NGX-HEADER-SEC-016"
    title = "Permissions-Policy does not disable baseline features"
    description = (
        "Detects HTTPS server blocks whose Permissions-Policy does not "
        "explicitly disable camera, microphone, and geolocation."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Disable browser features the application does not need, for example: "
        "`add_header Permissions-Policy "
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

                if policy is not None and policy.is_valid:
                    missing_features = tuple(
                        feature
                        for feature in _BASELINE_FEATURES
                        if feature not in policy.disabled_features
                    )
                else:
                    missing_features = _BASELINE_FEATURES

                if not missing_features:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "Permissions-Policy does not explicitly disable: "
                            f"{', '.join(missing_features)}."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)