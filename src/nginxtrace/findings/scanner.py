from nginxtrace.config.models import Directive
from nginxtrace.findings.models import Finding
from nginxtrace.rules.base import Rule

def scan(
        directives: tuple[Directive, ...],
        rules: tuple[Rule, ...],
) -> tuple[Finding]:
    findings: list[Finding] = []

    for rule in rules:
        findings.extend(rule.evaluate(directives))

    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.file.as_posix(),
                finding.line,
                finding.rule_id
            )
        )
    )