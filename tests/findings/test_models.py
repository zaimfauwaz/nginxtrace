import dataclasses
from pathlib import Path

import pytest

from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity


def make_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "rule_id": "NGX-TEST-001",
        "severity": Severity.HIGH,
        "title": "Test title",
        "message": "Test message.",
        "remediation": "Test remediation.",
        "confidence": Confidence.MEDIUM,
        "file": Path("nginx.conf"),
        "line": 12,
    }
    values.update(overrides)
    return Finding(**values)


def test_finding_stores_all_metadata() -> None:
    finding = make_finding(evidence=("root /var/www/app/public;",))

    assert finding.rule_id == "NGX-TEST-001"
    assert finding.severity == Severity.HIGH
    assert finding.title == "Test title"
    assert finding.message == "Test message."
    assert finding.remediation == "Test remediation."
    assert finding.confidence == Confidence.MEDIUM
    assert finding.file == Path("nginx.conf")
    assert finding.line == 12
    assert finding.evidence == ("root /var/www/app/public;",)


def test_finding_evidence_defaults_to_empty_tuple() -> None:
    finding = make_finding()

    assert finding.evidence == ()


def test_finding_is_frozen() -> None:
    finding = make_finding()

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(finding, "line", 99)
