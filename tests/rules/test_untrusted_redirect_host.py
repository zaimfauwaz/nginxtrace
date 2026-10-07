from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.untrusted_redirect_host import UntrustedRedirectHostRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return UntrustedRedirectHostRule().evaluate(directives)


def test_reports_https_redirect_with_http_host() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            return 301 https://$http_host$request_uri;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-REDIRECT-002"
    assert findings[0].line == 4
    assert findings[0].evidence == (
        "return 301 https://$http_host$request_uri;",
    )


def test_reports_temporary_https_redirect_with_http_host() -> None:
    findings = evaluate(
        """
        server {
            return 307 https://$http_host$request_uri;
        }
        """
    )

    assert len(findings) == 1


def test_reports_http_host_anywhere_in_https_target() -> None:
    findings = evaluate(
        """
        return 301 https://trusted.example/$http_host$request_uri;
        """
    )

    assert len(findings) == 1


def test_does_not_report_https_redirect_with_host() -> None:
    findings = evaluate(
        """
        return 301 https://$host$request_uri;
        """
    )

    assert findings == ()


def test_does_not_report_https_redirect_with_fixed_host() -> None:
    findings = evaluate(
        """
        return 301 https://example.com$request_uri;
        """
    )

    assert findings == ()


def test_does_not_report_http_redirect_with_http_host() -> None:
    findings = evaluate(
        """
        return 301 http://$http_host$request_uri;
        """
    )

    assert findings == ()


def test_does_not_report_non_redirect_return_with_http_host() -> None:
    findings = evaluate(
        """
        return 200 https://$http_host$request_uri;
        """
    )

    assert findings == ()


def test_does_not_report_non_return_directive_with_http_host() -> None:
    findings = evaluate(
        """
        proxy_set_header Host $http_host;
        """
    )

    assert findings == ()


def test_uses_medium_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        return 308 https://$http_host$request_uri;
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.HIGH