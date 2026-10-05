from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.weak_x_frame_options import WeakXFrameOptionsRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return WeakXFrameOptionsRule().evaluate(directives)


def test_does_not_report_when_x_frame_options_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_deny() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options DENY always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_sameorigin() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options SAMEORIGIN always;
        }
        """
    )

    assert findings == ()


def test_reports_allow_from_with_uri() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options ALLOW-FROM https://trusted.example;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-008"
    assert "invalid or obsolete" in findings[0].message


def test_reports_allow_from_without_uri() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options ALLOW-FROM;
        }
        """
    )

    assert len(findings) == 1


def test_reports_same_origin_with_hyphen() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options SAME-ORIGIN;
        }
        """
    )

    assert len(findings) == 1


def test_reports_arbitrary_value() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options ALLOWALL;
        }
        """
    )

    assert len(findings) == 1


def test_reports_empty_value() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options "";
        }
        """
    )

    assert len(findings) == 1


def test_reports_value_with_extra_tokens() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options "DENY extra";
        }
        """
    )

    assert len(findings) == 1


def test_reports_only_invalid_header_when_multiple_headers_exist() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options DENY;
            add_header X-Frame-Options ALLOW-FROM https://trusted.example;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].line == 5


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header X-Frame-Options ALLOW-FROM https://trusted.example;
        }
        """
    )

    assert findings == ()


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options ALLOW-FROM https://trusted.example;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH