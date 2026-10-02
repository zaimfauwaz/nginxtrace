from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

DANGEROUS_ROOTS = {"/", "/etc", "/etc/", "/root", "/root/"}

class DangerousRootRule(Rule):
    rule_id = "NGX-ROOT-001"
    title = "Dangerous root directory"
    description = (
        "Detects a root directive that points at a system directory "
        "such as /, /etc, or /root."
    )
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    remediation = (
        "Point root at a dedicated web directory that only contains "
        "public files, such as /var/www/app/public."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message=f"The root directive points at {directive.arguments[0]}.",
                evidence=(format_directive(directive),),
            )
            for directive in find_directives(directives, "root")
            if directive.arguments and directive.arguments[0] in DANGEROUS_ROOTS
        )
