from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.nested_nosniff_override import NestedNosniffOverrideRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return NestedNosniffOverrideRule().evaluate(directives)

def test_reports_location_that_drops_parent_nosniff() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Content-Type-Options nosniff always;

            location /assets/ {
                add_header Cache-Control "public, max-age=3600";
            }
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-002"
    assert findings[0].line == 6
    assert "drops inherited" in findings[0].message


def test_does_not_report_location_that_repeats_nosniff() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Content-Type-Options nosniff always;

            location /assets/ {
                add_header Cache-Control "public, max-age=3600";
                add_header X-Content-Type-Options nosniff always;
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
            add_header X-Content-Type-Options nosniff always;

            location /assets/ {
                try_files $uri =404;
            }
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_parent_does_not_define_nosniff() -> None:
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
            add_header X-Content-Type-Options nosniff;

            location /assets/ {
                add_header Cache-Control public;
            }
        }
        """
    )

    assert findings == ()


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header X-Content-Type-Options nosniff;

            location / {
                add_header Cache-Control no-store;
            }
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH