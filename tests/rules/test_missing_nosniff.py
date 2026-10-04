from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.missing_nosniff import MissingNosniffRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return MissingNosniffRule().evaluate(directives)


def test_reports_https_server_without_nosniff() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-001"
    assert "X-Content-Type-Options" in findings[0].message


def test_does_not_report_https_server_with_nosniff() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Content-Type-Options nosniff always;
        }
        """
    )

    assert findings == ()


def test_reports_https_server_when_nosniff_header_has_wrong_value() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Content-Type-Options off;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-001"


def test_does_not_report_http_only_server_without_nosniff() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
        }
        """
    )

    assert findings == ()


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH