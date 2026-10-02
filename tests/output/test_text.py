from pathlib import Path

from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.output.text import format_finding, format_findings, format_summary


def make_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "rule_id": "NGX-TEST-001",
        "severity": Severity.LOW,
        "title": "Test title",
        "message": "Test finding.",
        "remediation": "Test remediation.",
        "confidence": Confidence.MEDIUM,
        "file": Path("nginx.conf"),
        "line": 1,
    }
    values.update(overrides)
    return Finding(**values)


def test_format_finding_formats_one_finding() -> None:
    finding = make_finding(
        rule_id="NGX-SECRET-001",
        severity=Severity.HIGH,
        title="Potential sensitive dotfile exposure",
        message="A root directive was found.",
        remediation="Add a dotfile denial location.",
        confidence=Confidence.MEDIUM,
        file=Path("conf.d/app.conf"),
        line=12,
        evidence=("root /var/www/app/public;",),
    )

    result = format_finding(finding)

    assert result == (
        "HIGH     NGX-SECRET-001\n"
        "Potential sensitive dotfile exposure\n"
        "\n"
        "File: conf.d/app.conf:12\n"
        "Confidence: medium\n"
        "\n"
        "A root directive was found.\n"
        "\n"
        "Remediation:\n"
        "Add a dotfile denial location.\n"
        "\n"
        "Evidence:\n"
        "root /var/www/app/public;"
    )


def test_format_finding_omits_evidence_section_when_empty() -> None:
    result = format_finding(make_finding())

    assert "Evidence:" not in result
    assert result.endswith("Remediation:\nTest remediation.")


def test_format_finding_prints_each_evidence_line() -> None:
    finding = make_finding(
        evidence=(
            "root /var/www/app/public;",
            "location / {",
        ),
    )

    result = format_finding(finding)

    assert result.endswith(
        "Evidence:\n"
        "root /var/www/app/public;\n"
        "location / {"
    )


def test_format_finding_uses_posix_path_format() -> None:
    finding = make_finding(
        file=Path("conf.d") / "sites" / "app.conf",
        line=3,
    )

    result = format_finding(finding)

    assert "File: conf.d/sites/app.conf:3\n" in result


def test_format_findings_returns_no_findings_message() -> None:
    result = format_findings(())

    assert result == "No findings."


def test_format_findings_separates_multiple_findings() -> None:
    first_finding = make_finding(rule_id="NGX-FIRST-001", line=1)
    second_finding = make_finding(rule_id="NGX-SECOND-001", line=2)

    result = format_findings(
        (
            first_finding,
            second_finding,
        )
    )

    assert result == (
        format_finding(first_finding)
        + "\n\n"
        + format_finding(second_finding)
        + "\n\n"
        + "2 findings (2 low)"
    )


def test_format_summary_counts_by_severity_from_highest() -> None:
    findings = (
        make_finding(severity=Severity.LOW),
        make_finding(severity=Severity.HIGH),
        make_finding(severity=Severity.LOW),
    )

    assert format_summary(findings) == "3 findings (1 high, 2 low)"


def test_format_summary_uses_singular_for_one_finding() -> None:
    assert format_summary((make_finding(severity=Severity.MEDIUM),)) == (
        "1 finding (1 medium)"
    )
