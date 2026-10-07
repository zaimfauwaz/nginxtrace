from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive, walk_directives
from nginxtrace.rules.https_redirect import https_return_redirect


_UNTRUSTED_HOST_VARIABLE = "$http_host"


class UntrustedRedirectHostRule(Rule):
    rule_id = "NGX-REDIRECT-002"
    title = "HTTP redirect uses untrusted host value"
    description = (
        "Detects direct HTTPS return redirects that construct the target "
        "URL with the raw client-supplied $http_host variable."
    )
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH
    remediation = (
        "Use a fixed trusted hostname or a validated host value when "
        "constructing external redirect URLs. Avoid $http_host in "
        "redirect targets."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in walk_directives(directives):
            redirect = https_return_redirect(directive)

            if redirect is None:
                continue

            if _UNTRUSTED_HOST_VARIABLE not in redirect.target:
                continue

            findings.append(
                self.create_finding(
                    directive,
                    message=(
                        "HTTPS redirect target uses $http_host, which "
                        "reflects raw client-supplied Host input."
                    ),
                    evidence=(format_directive(directive),),
                )
            )

        return tuple(findings)