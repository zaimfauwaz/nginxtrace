from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.missing_referrer_policy import MissingReferrerPolicyRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return MissingReferrerPolicyRule().evaluate(directives)


def test_reports_https_server_without_referrer_policy() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-011"
    assert "Referrer-Policy" in findings[0].message


def test_does_not_report_https_server_with_recommended_referrer_policy() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy strict-origin-when-cross-origin always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_referrer_policy_is_unsafe() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy unsafe-url;
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server_without_referrer_policy() -> None:
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
            add_header referrer-policy strict-origin-when-cross-origin;
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