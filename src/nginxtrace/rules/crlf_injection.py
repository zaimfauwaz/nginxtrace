import re

from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import walk_directives, format_directive

CHECKED_DIRECTIVES = {"rewrite", "return", "add_header", "proxy_set_header", "proxy_pass"}
DECODED_URI_VARIABLE = re.compile(r"\$\{?(uri|document_uri)\b")

class CrlfInjectionRule(Rule):
    rule_id = "NGX-CRLF-001"
    title = "Possible CRLF injection via decoded URI"
    description = (
        "Detects $uri or $document_uri in directives that build URLs or "
        "headers. These variables are URL-decoded and may contain line breaks."
    )
    default_severity = Severity.HIGH
    default_confidence = Confidence.MEDIUM
    remediation = "Use $request_uri, which is not decoded, instead of $uri or $document_uri."

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return tuple(
            self.create_finding(
                directive,
                message=f"{directive.name} uses a decoded URI variable.",
                evidence=(format_directive(directive),),
            )
            for directive in walk_directives(directives)
            if directive.name in CHECKED_DIRECTIVES
            and any(DECODED_URI_VARIABLE.search(argument) for argument in directive.arguments)
        )
