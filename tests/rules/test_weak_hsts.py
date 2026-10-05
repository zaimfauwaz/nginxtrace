from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.weak_hsts import WeakHstsRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return WeakHstsRule().evaluate(directives)


def test_does_not_report_when_hsts_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_reports_hsts_without_max_age() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security includeSubDomains;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-004"
    assert "max-age" in findings[0].message


def test_reports_hsts_with_non_numeric_max_age() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=abc";
        }
        """
    )

    assert len(findings) == 1


def test_reports_hsts_with_zero_max_age() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=0";
        }
        """
    )

    assert len(findings) == 1


def test_reports_hsts_with_short_max_age() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=86400";
        }
        """
    )

    assert len(findings) == 1


def test_does_not_report_hsts_at_minimum_max_age() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=15768000";
        }
        """
    )

    assert findings == ()


def test_does_not_report_hsts_above_minimum_max_age() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security
                "max-age=31536000; includeSubDomains" always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header Strict-Transport-Security "max-age=0";
        }
        """
    )

    assert findings == ()


def test_finding_uses_header_directive_location() -> None:
    findings = evaluate(
        """server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=0";
}
"""
    )

    assert len(findings) == 1
    assert findings[0].line == 3


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=0";
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH