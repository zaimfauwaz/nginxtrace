from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.secret_exposure import SecretExposureRule


def test_rule_returns_no_findings_without_root_directive() -> None:
    directives = parse(
        "server {\n"
        "    listen 80;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = SecretExposureRule().evaluate(directives)

    assert findings == ()


def test_rule_reports_unprotected_root_directive() -> None:
    directives = parse(
        "server {\n"
        "    root /var/www/app/public;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = SecretExposureRule().evaluate(directives)

    assert len(findings) == 1

    finding = findings[0]
    assert finding.rule_id == "NGX-SECRET-001"
    assert finding.severity == Severity.HIGH
    assert finding.message == (
        "A root directive was found, but no dotfile denial "
        "location was detected."
    )
    assert finding.file == Path("nginx.conf")
    assert finding.line == 2


def test_rule_returns_no_findings_with_dotfile_protection() -> None:
    directives = parse(
        "server {\n"
        "    root /var/www/app/public;\n"
        "\n"
        "    location ~ /\\. {\n"
        "        deny all;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = SecretExposureRule().evaluate(directives)

    assert findings == ()


def test_rule_reports_each_unprotected_root_directive() -> None:
    directives = parse(
        "http {\n"
        "    server {\n"
        "        root /var/www/site-a/public;\n"
        "    }\n"
        "\n"
        "    server {\n"
        "        root /var/www/site-b/public;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = SecretExposureRule().evaluate(directives)

    assert len(findings) == 2
    assert [finding.line for finding in findings] == [3, 7]