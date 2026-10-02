from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.registry import default_rules, find_rule
from nginxtrace.rules.secret_exposure import SecretExposureRule


def test_default_rules_include_secret_exposure_rule() -> None:
    assert any(
        isinstance(rule, SecretExposureRule) for rule in default_rules()
    )


def test_default_rule_ids_are_unique() -> None:
    rule_ids = [rule.rule_id for rule in default_rules()]

    assert len(rule_ids) == len(set(rule_ids))


def test_every_default_rule_defines_metadata() -> None:
    for rule in default_rules():
        assert rule.rule_id
        assert rule.title
        assert rule.description
        assert isinstance(rule.default_severity, Severity)
        assert isinstance(rule.default_confidence, Confidence)
        assert rule.remediation


def test_find_rule_returns_matching_rule() -> None:
    rule = find_rule("NGX-SECRET-001")

    assert isinstance(rule, SecretExposureRule)


def test_find_rule_returns_none_for_unknown_rule_id() -> None:
    assert find_rule("NGX-UNKNOWN-999") is None


def test_default_rules_include_all_phase_4_rules() -> None:
    assert [rule.rule_id for rule in default_rules()] == [
        "NGX-SECRET-001",
        "NGX-ROOT-001",
        "NGX-SLASH-001",
        "NGX-HOST-001",
        "NGX-REFERER-001",
        "NGX-CRLF-001",
        "NGX-HEADER-ML-001",
        "NGX-ALIAS-001",
        "NGX-MAP-001",
        "NGX-SSRF-001",
        "NGX-HEADER-001",
        "NGX-PROXY-ERR-001",
    ]
