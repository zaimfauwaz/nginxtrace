from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.http_to_https_redirect import HttpToHttpsRedirectRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return HttpToHttpsRedirectRule().evaluate(directives)


def test_reports_server_with_port_80_listener_without_redirect() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            server_name example.com;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-REDIRECT-001"
    assert findings[0].line == 3
    assert findings[0].evidence == ("listen 80;",)


def test_does_not_report_server_with_301_https_return() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 301 https://$host$request_uri;
        }
        """
    )

    assert findings == ()


def test_does_not_report_server_with_308_https_return() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 308 https://$host$request_uri;
        }
        """
    )

    assert findings == ()


def test_reports_http_redirect_target() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 301 http://example.com$request_uri;
        }
        """
    )

    assert len(findings) == 1


def test_reports_scheme_variable_redirect_target() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 301 $scheme://$host$request_uri;
        }
        """
    )

    assert len(findings) == 1


def test_does_not_report_https_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_non_standard_http_port() -> None:
    findings = evaluate(
        """
        server {
            listen 8080;
        }
        """
    )

    assert findings == ()


def test_ignores_top_level_listen_directive() -> None:
    findings = evaluate(
        """
        listen 80;
        """
    )

    assert findings == ()


def test_reports_each_port_80_listener_without_redirect() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            listen [::]:80;
        }
        """
    )

    assert len(findings) == 2
    assert tuple(finding.line for finding in findings) == (3, 4)


def test_reports_location_level_redirect_as_not_server_wide() -> None:
    findings = evaluate(
        """
        server {
            listen 80;

            location / {
                return 301 https://$host$request_uri;
            }
        }
        """
    )

    assert len(findings) == 1


def test_uses_low_severity_and_medium_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.MEDIUM