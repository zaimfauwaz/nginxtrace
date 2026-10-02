import json
from pathlib import Path

from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.output.json import finding_to_dict, format_findings


def make_finding() -> Finding:
    return Finding(
        rule_id="NGX-SECRET-001",
        severity=Severity.HIGH,
        title="Potential sensitive dotfile exposure",
        message="A root directive was found.",
        remediation="Add a dotfile denial location.",
        confidence=Confidence.MEDIUM,
        file=Path("conf.d") / "app.conf",
        line=12,
        evidence=("root /var/www/app/public;",),
    )


def test_finding_to_dict_uses_plain_json_values() -> None:
    assert finding_to_dict(make_finding()) == {
        "rule_id": "NGX-SECRET-001",
        "severity": "high",
        "confidence": "medium",
        "title": "Potential sensitive dotfile exposure",
        "message": "A root directive was found.",
        "remediation": "Add a dotfile denial location.",
        "file": "conf.d/app.conf",
        "line": 12,
        "evidence": ["root /var/www/app/public;"],
    }


def test_format_findings_returns_valid_json() -> None:
    result = json.loads(format_findings((make_finding(),)))

    assert result["total"] == 1
    assert result["findings"][0]["rule_id"] == "NGX-SECRET-001"


def test_format_findings_returns_empty_list_without_findings() -> None:
    assert json.loads(format_findings(())) == {"total": 0, "findings": []}
