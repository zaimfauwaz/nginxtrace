from pathlib import Path

from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.policy.models import Policy, Suppression


def make_finding(file: str = "nginx.conf", line: int = 7) -> Finding:
    return Finding(
        rule_id="NGX-SECRET-001",
        severity=Severity.HIGH,
        title="Test title",
        message="Test message.",
        remediation="Test remediation.",
        confidence=Confidence.MEDIUM,
        file=Path(file),
        line=line,
    )


def test_suppression_matches_rule_file_and_line() -> None:
    suppression = Suppression("NGX-SECRET-001", "nginx.conf", "Accepted", line=7)

    assert suppression.matches(make_finding())


def test_suppression_without_line_matches_any_line() -> None:
    suppression = Suppression("NGX-SECRET-001", "nginx.conf", "Accepted")

    assert suppression.matches(make_finding(line=99))


def test_suppression_does_not_match_other_line() -> None:
    suppression = Suppression("NGX-SECRET-001", "nginx.conf", "Accepted", line=8)

    assert not suppression.matches(make_finding())


def test_suppression_does_not_match_other_rule() -> None:
    suppression = Suppression("NGX-ROOT-001", "nginx.conf", "Accepted")

    assert not suppression.matches(make_finding())


def test_suppression_requires_exact_file_path() -> None:
    suppression = Suppression("NGX-SECRET-001", "nginx.conf", "Accepted")

    assert not suppression.matches(make_finding(file="conf.d/nginx.conf"))


def test_policy_defaults_change_nothing() -> None:
    policy = Policy()

    assert policy.min_severity is None
    assert policy.disabled_rules == frozenset()
    assert policy.severity_overrides == {}
    assert policy.suppressions == ()
