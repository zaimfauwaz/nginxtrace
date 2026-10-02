from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

class HostSpoofingRule(Rule):
    rule_id = "NGX-HOST-001"
    title = "Host header forwarded from $http_host"
    description = (
        "Detects proxy_set_header Host using $http_host, which forwards "
        "the client-supplied Host header unchanged."
    )
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH
    remediation = "Use proxy_set_header Host $host; instead of $http_host."

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message="The proxied Host header is set from $http_host.",
                evidence=(format_directive(directive),),
            )
            for directive in find_directives(directives, "proxy_set_header")
            if len(directive.arguments) >= 2
            and directive.arguments[0].lower() == "host"
            and "$http_host" in directive.arguments[1]
        )
