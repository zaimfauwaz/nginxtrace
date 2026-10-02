from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

def proxy_host(argument: str) -> str:
    target = argument.split("://", 1)[-1]
    return target.split("/", 1)[0]

class SsrfRule(Rule):
    rule_id = "NGX-SSRF-001"
    title = "Possible SSRF via variable proxy_pass host"
    description = (
        "Detects proxy_pass whose target host comes from a variable, in a "
        "location that is not marked internal."
    )
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.MEDIUM
    remediation = (
        "Use a fixed upstream host, or mark the location internal and make "
        "sure the variable cannot be controlled by the client."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for location in find_directives(directives, "location"):
            children = location.children or ()

            if any(child.name == "internal" for child in children):
                continue

            for child in children:
                if child.name == "proxy_pass" and child.arguments and proxy_host(child.arguments[0]).startswith("$"):
                    findings.append(
                        self.create_finding(
                            child,
                            message="proxy_pass builds its target host from a variable.",
                            evidence=(format_directive(location), format_directive(child)),
                        )
                    )

        return tuple(findings)
