from pathlib import Path

from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.output.text import format_finding, format_findings


def test_format_finding_formats_one_finding() -> None:
    finding = Finding(
        rule_id="NGX-SECRET-001",
        severity=Severity.HIGH,
        message="A root directive was found.",
        file=Path("conf.d/app.conf"),
        line=12,
    )

    result = format_finding(finding)

    assert result == (
        "HIGH     NGX-SECRET-001\n"
        "A root directive was found.\n"
        "File: conf.d/app.conf:12"
    )


def test_format_finding_uses_posix_path_format() -> None:
    finding = Finding(
        rule_id="NGX-TEST-001",
        severity=Severity.LOW,
        message="Test finding.",
        file=Path("conf.d") / "sites" / "app.conf",
        line=3,
    )

    result = format_finding(finding)

    assert result.endswith("File: conf.d/sites/app.conf:3")


def test_format_findings_returns_no_findings_message() -> None:
    result = format_findings(())

    assert result == "No findings."


def test_format_findings_separates_multiple_findings() -> None:
    first_finding = Finding(
        rule_id="NGX-FIRST-001",
        severity=Severity.HIGH,
        message="First finding.",
        file=Path("nginx.conf"),
        line=1,
    )
    second_finding = Finding(
        rule_id="NGX-SECOND-001",
        severity=Severity.MEDIUM,
        message="Second finding.",
        file=Path("nginx.conf"),
        line=2,
    )

    result = format_findings(
        (
            first_finding,
            second_finding,
        )
    )

    assert result == (
        "HIGH     NGX-FIRST-001\n"
        "First finding.\n"
        "File: nginx.conf:1\n"
        "\n"
        "MEDIUM   NGX-SECOND-001\n"
        "Second finding.\n"
        "File: nginx.conf:2"
    )