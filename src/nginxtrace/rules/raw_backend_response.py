from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import walk_directives, format_directive

class RawBackendResponseRule(Rule):
    rule_id = "NGX-PROXY-ERR-001"
    title = "proxy_hide_header may not hide backend headers"
    description = (
        "Detects proxy_hide_header in the same block as proxy_intercept_errors on. "
        "Requests NGINX cannot parse may return the raw backend response, "
        "including headers meant to be hidden."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.LOW
    remediation = (
        "Remove sensitive headers in the backend application itself instead "
        "of relying on proxy_hide_header."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for block in walk_directives(directives):
            children = block.children or ()

            if not any(
                child.name == "proxy_intercept_errors" and child.arguments == ("on",)
                for child in children
            ):
                continue

            for child in children:
                if child.name == "proxy_hide_header":
                    findings.append(
                        self.create_finding(
                            child,
                            message="proxy_hide_header is combined with proxy_intercept_errors on.",
                            evidence=(format_directive(child),),
                        )
                    )

        return tuple(findings)
