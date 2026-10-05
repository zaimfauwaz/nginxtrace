from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.missing_hsts import MissingHstsRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return MissingHstsRule().evaluate(directives)


def test_reports_https_server_without_hsts() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-003"
    assert "Strict-Transport-Security" in findings[0].message


def test_does_not_report_https_server_with_hsts() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=31536000" always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_hsts_max_age_is_zero() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=0";
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server_without_hsts() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_header_name_uses_different_case() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header strict-transport-security "max-age=31536000";
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