from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive
from nginxtrace.rules.security_headers import (
    ReferrerPolicyClass,
    direct_headers,
    is_https_server,
    referrer_policy_class,
)


class WeakReferrerPolicyRule(Rule):
    rule_id = "NGX-HEADER-SEC-012"
    title = "Referrer-Policy is unsafe, overly permissive, or invalid"
    description = (
        "Detects HTTPS server blocks that define Referrer-Policy with an "
        "unsafe, overly permissive, or unrecognized value."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Use a restrictive Referrer-Policy such as "
        "`strict-origin-when-cross-origin`, for example: "
        "`add_header Referrer-Policy strict-origin-when-cross-origin always;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in directives:
            if directive.name != "server":
                continue

            if not is_https_server(directive):
                continue

            for header in direct_headers(directive):
                if header.name != "referrer-policy":
                    continue

                policy_class = referrer_policy_class(header)

                if policy_class is ReferrerPolicyClass.RECOMMENDED:
                    continue

                if policy_class is None:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "Referrer-Policy is unsafe, overly permissive, "
                            "or invalid; use strict-origin-when-cross-origin "
                            "or a stricter policy."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)