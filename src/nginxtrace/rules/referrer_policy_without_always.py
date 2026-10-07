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


class ReferrerPolicyWithoutAlwaysRule(Rule):
    rule_id = "NGX-HEADER-SEC-014"
    title = "Referrer-Policy is not configured with always"
    description = (
        "Detects recommended Referrer-Policy headers on HTTPS server blocks "
        "that are not configured with the NGINX always parameter."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "Add the always parameter to the Referrer-Policy directive, for "
        "example: `add_header Referrer-Policy "
        "strict-origin-when-cross-origin always;`."
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

                if (
                        referrer_policy_class(header)
                        is not ReferrerPolicyClass.RECOMMENDED
                ):
                    continue

                if header.always:
                    continue

                findings.append(
                    self.create_finding(
                        header.directive,
                        message=(
                            "Referrer-Policy is not configured with the "
                            "always parameter."
                        ),
                        evidence=(format_directive(header.directive),),
                    )
                )

        return tuple(findings)