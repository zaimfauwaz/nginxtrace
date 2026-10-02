from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import walk_directives, format_directive

def first_add_header(block: Directive) -> Directive | None:
    for child in block.children or ():
        if child.name == "add_header":
            return child
    return None

class HeaderRedefinitionRule(Rule):
    rule_id = "NGX-HEADER-001"
    title = "add_header redefinition drops parent headers"
    description = (
        "Detects a nested block with its own add_header inside a block that "
        "also uses add_header. NGINX then ignores the outer add_header values."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.MEDIUM
    remediation = (
        "Repeat the parent add_header directives in the nested block, or "
        "move all add_header directives to one level."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for block in walk_directives(directives):
            if first_add_header(block) is None:
                continue

            for child in block.children or ():
                nested_header = first_add_header(child)

                if nested_header is not None:
                    findings.append(
                        self.create_finding(
                            nested_header,
                            message=(
                                f"add_header in {child.name} replaces the add_header "
                                f"directives from {block.name}."
                            ),
                            evidence=(format_directive(child), format_directive(nested_header)),
                        )
                    )

        return tuple(findings)
