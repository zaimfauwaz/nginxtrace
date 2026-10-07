from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.temporary_https_redirect import (
    TemporaryHttpsRedirectRule,
)


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return TemporaryHttpsRedirectRule().evaluate(directives)


def test_reports_302_https_redirect_from_port_80_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 302 https://$host$request_uri;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-REDIRECT-003"
    assert findings[0].line == 4
    assert "temporary status 302" in findings[0].message


def test_reports_307_https_redirect_from_port_80_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 307 https://$host$request_uri;
        }
        """
    )

    assert len(findings) == 1
    assert "temporary status 307" in findings[0].message


def test_does_not_report_301_https_redirect() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 301 https://$host$request_uri;
        }
        """
    )

    assert findings == ()


def test_does_not_report_308_https_redirect() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 308 https://$host$request_uri;
        }
        """
    )

    assert findings == ()


def test_does_not_report_303_https_redirect() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 303 https://$host$request_uri;
        }
        """
    )

    assert findings == ()


def test_does_not_report_temporary_https_redirect_without_port_80() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            return 302 https://$host$request_uri;
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_target() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 302 http://example.com$request_uri;
        }
        """
    )

    assert findings == ()


def test_does_not_report_location_level_temporary_redirect() -> None:
    findings = evaluate(
        """
        server {
            listen 80;

            location / {
                return 302 https://$host$request_uri;
            }
        }
        """
    )

    assert findings == ()


def test_reports_each_temporary_https_redirect() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 302 https://one.example$request_uri;
            return 307 https://two.example$request_uri;
        }
        """
    )

    assert len(findings) == 2
    assert tuple(finding.line for finding in findings) == (4, 5)


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 302 https://$host$request_uri;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH