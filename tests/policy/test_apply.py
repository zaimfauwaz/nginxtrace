from pathlib import Path

from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.policy.apply import apply_policy
from nginxtrace.policy.models import Policy, Suppression


def make_finding(rule_id: str, line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW,
        title="Test title",
        message="Test message.",
        remediation="Test remediation.",
        confidence=Confidence.MEDIUM,
        file=Path("nginx.conf"),
        line=line,
    )


def test_empty_policy_keeps_every_finding() -> None:
    findings = (make_finding("NGX-MAP-001"), make_finding("NGX-ROOT-001"))

    assert apply_policy(findings, Policy()) == (findings, ())


def test_disabled_rule_findings_are_dropped() -> None:
    findings = (make_finding("NGX-MAP-001"), make_finding("NGX-ROOT-001"))
    policy = Policy(disabled_rules=frozenset({"NGX-MAP-001"}))

    kept, suppressed = apply_policy(findings, policy)

    assert [finding.rule_id for finding in kept] == ["NGX-ROOT-001"]
    assert suppressed == ()


def test_severity_override_changes_finding_severity() -> None:
    policy = Policy(severity_overrides={"NGX-MAP-001": Severity.HIGH})

    kept, _ = apply_policy((make_finding("NGX-MAP-001"),), policy)

    assert kept[0].severity == Severity.HIGH


def test_matching_finding_is_moved_to_suppressed_with_reason() -> None:
    suppression = Suppression("NGX-MAP-001", "nginx.conf", "Accepted risk", line=3)
    findings = (make_finding("NGX-MAP-001", line=3), make_finding("NGX-MAP-001", line=4))

    kept, suppressed = apply_policy(findings, Policy(suppressions=(suppression,)))

    assert [finding.line for finding in kept] == [4]
    assert len(suppressed) == 1
    assert suppressed[0].finding.line == 3
    assert suppressed[0].suppression.reason == "Accepted risk"


def test_suppressed_finding_keeps_overridden_severity() -> None:
    policy = Policy(
        severity_overrides={"NGX-MAP-001": Severity.HIGH},
        suppressions=(Suppression("NGX-MAP-001", "nginx.conf", "Accepted"),),
    )

    _, suppressed = apply_policy((make_finding("NGX-MAP-001"),), policy)

    assert suppressed[0].finding.severity == Severity.HIGH
