from pathlib import Path

from nginxtrace.config.models import Directive
from nginxtrace.findings.models import Finding
from nginxtrace.findings.scanner import scan
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule


class StaticRule(Rule):
    rule_id = "TEST-STATIC-001"
    title = "Static test rule"

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        self.findings = findings

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        return self.findings


def test_scan_returns_empty_tuple_when_rules_find_nothing() -> None:
    findings = scan(
        directives=(),
        rules=(StaticRule(()),),
    )

    assert findings == ()


def test_scan_collects_findings_from_multiple_rules() -> None:
    first_finding = Finding(
        rule_id="TEST-FIRST-001",
        severity=Severity.HIGH,
        message="First finding.",
        file=Path("nginx.conf"),
        line=1,
    )
    second_finding = Finding(
        rule_id="TEST-SECOND-001",
        severity=Severity.MEDIUM,
        message="Second finding.",
        file=Path("nginx.conf"),
        line=2,
    )

    findings = scan(
        directives=(),
        rules=(
            StaticRule((first_finding,)),
            StaticRule((second_finding,)),
        ),
    )

    assert findings == (
        first_finding,
        second_finding,
    )


def test_scan_sorts_findings_by_file_line_and_rule_id() -> None:
    finding_in_second_file = Finding(
        rule_id="TEST-SECOND-FILE-001",
        severity=Severity.LOW,
        message="Second file finding.",
        file=Path("sites-enabled/b.conf"),
        line=1,
    )
    finding_on_later_line = Finding(
        rule_id="TEST-LATER-LINE-001",
        severity=Severity.LOW,
        message="Later line finding.",
        file=Path("sites-enabled/a.conf"),
        line=10,
    )
    finding_on_earlier_line = Finding(
        rule_id="TEST-EARLIER-LINE-001",
        severity=Severity.LOW,
        message="Earlier line finding.",
        file=Path("sites-enabled/a.conf"),
        line=2,
    )
    finding_same_line_later_rule = Finding(
        rule_id="TEST-Z-001",
        severity=Severity.LOW,
        message="Later rule identifier.",
        file=Path("sites-enabled/a.conf"),
        line=2,
    )

    findings = scan(
        directives=(),
        rules=(
            StaticRule(
                (
                    finding_in_second_file,
                    finding_on_later_line,
                )
            ),
            StaticRule(
                (
                    finding_same_line_later_rule,
                    finding_on_earlier_line,
                )
            ),
        ),
    )

    assert findings == (
        finding_on_earlier_line,
        finding_same_line_later_rule,
        finding_on_later_line,
        finding_in_second_file,
    )


def test_scan_passes_directives_to_each_rule() -> None:
    directives = (
        Directive(
            name="server",
            arguments=(),
            file=Path("nginx.conf"),
            line=1,
            children=(),
        ),
    )
    rule = StaticRule(())

    findings = scan(
        directives=directives,
        rules=(rule,),
    )

    assert findings == ()