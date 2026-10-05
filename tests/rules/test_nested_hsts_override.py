from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.nested_hsts_override import NestedHstsOverrideRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return NestedHstsOverrideRule().evaluate(directives)


def test_reports_location_that_drops_parent_hsts() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=31536000" always;

            location /assets/ {
                add_header Cache-Control "public, max-age=3600";
            }
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-005"
    assert "drops inherited" in findings[0].message


def test_does_not_report_location_that_repeats_hsts() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=31536000" always;

            location /assets/ {
                add_header Cache-Control "public, max-age=3600";
                add_header Strict-Transport-Security "max-age=31536000" always;
            }
        }
        """
    )

    assert findings == ()


def test_does_not_report_location_without_its_own_add_header() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=31536000" always;

            location /assets/ {
                try_files $uri =404;
            }
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_parent_does_not_define_hsts() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;

            location /assets/ {
                add_header Cache-Control "public, max-age=3600";
            }
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header Strict-Transport-Security "max-age=31536000";

            location /assets/ {
                add_header Cache-Control public;
            }
        }
        """
    )

    assert findings == ()


def test_finding_uses_nested_block_location() -> None:
    findings = evaluate(
        """server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location / {
        add_header Cache-Control no-store;
    }
}
"""
    )

    assert len(findings) == 1
    assert findings[0].line == 4


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Strict-Transport-Security "max-age=31536000";

            location / {
                add_header Cache-Control no-store;
            }
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH