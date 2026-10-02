from nginxtrace.findings.severity import Severity, meets_threshold


def test_critical_meets_high_threshold() -> None:
    assert meets_threshold(Severity.CRITICAL, Severity.HIGH)


def test_high_meets_high_threshold() -> None:
    assert meets_threshold(Severity.HIGH, Severity.HIGH)


def test_medium_does_not_meet_high_threshold() -> None:
    assert not meets_threshold(Severity.MEDIUM, Severity.HIGH)


def test_info_does_not_meet_low_threshold() -> None:
    assert not meets_threshold(Severity.INFO, Severity.LOW)