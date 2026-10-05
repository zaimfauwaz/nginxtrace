from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.missing_x_frame_options import MissingXFrameOptionsRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return MissingXFrameOptionsRule().evaluate(directives)


def test_reports_https_server_without_x_frame_options() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-007"
    assert "X-Frame-Options" in findings[0].message


def test_does_not_report_https_server_with_deny() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options DENY always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_https_server_with_sameorigin() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options SAMEORIGIN always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_x_frame_options_has_invalid_value() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options ALLOW-FROM https://trusted.example;
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server_without_x_frame_options() -> None:
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
            add_header x-frame-options deny;
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