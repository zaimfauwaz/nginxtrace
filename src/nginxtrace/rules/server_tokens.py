from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive


class ServerTokensEnabledRule(Rule):
    rule_id = "NGX-INFO-001"

    title = "NGINX version disclosure is enabled"

    description = (
        "Detects server_tokens on, which exposes NGINX version information "
        "in generated response headers and error pages."
    )

    default_severity = Severity.LOW

    default_confidence = Confidence.HIGH

    remediation = (
        "Set server_tokens off; in an appropriate http or server context. "
        "This reduces fingerprinting but does not replace patching."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message="server_tokens is explicitly enabled.",
                evidence=(format_directive(directive),),
            )
            for directive in find_directives(directives, "server_tokens")
            if directive.arguments == ("on",)
        )