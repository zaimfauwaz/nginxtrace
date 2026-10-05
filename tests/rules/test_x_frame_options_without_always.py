from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.x_frame_options_without_always import (
    XFrameOptionsWithoutAlwaysRule,
)


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return XFrameOptionsWithoutAlwaysRule().evaluate(directives)


def test_does_not_report_when_x_frame_options_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_invalid_x_frame_options_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options ALLOW-FROM https://trusted.example;
        }
        """
    )

    assert findings == ()


def test_does_not_report_hyphenated_same_origin_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options SAME-ORIGIN;
        }
        """
    )

    assert findings == ()


def test_reports_deny_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options DENY;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-010"
    assert "always" in findings[0].message


def test_reports_sameorigin_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options SAMEORIGIN;
        }
        """
    )

    assert len(findings) == 1


def test_does_not_report_deny_with_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options DENY always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_sameorigin_with_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Frame-Options SAMEORIGIN always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header X-Frame-Options DENY;
        }
        """
    )

    assert findings == ()


def test_finding_uses_x_frame_options_directive_location() -> None:
    findings = evaluate(
        """server {
    listen 443 ssl;
    add_header X-Frame-Options DENY;
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
            add_header X-Frame-Options DENY;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH