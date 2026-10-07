from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.referrer_policy_without_always import (
    ReferrerPolicyWithoutAlwaysRule,
)


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return ReferrerPolicyWithoutAlwaysRule().evaluate(directives)


def test_does_not_report_when_referrer_policy_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_permissive_referrer_policy_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy origin;
        }
        """
    )

    assert findings == ()


def test_does_not_report_invalid_referrer_policy_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy unsafe-url;
        }
        """
    )

    assert findings == ()


def test_reports_recommended_policy_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy strict-origin-when-cross-origin;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-014"
    assert "always" in findings[0].message


def test_reports_no_referrer_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy no-referrer;
        }
        """
    )

    assert len(findings) == 1


def test_does_not_report_recommended_policy_with_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy strict-origin-when-cross-origin always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header Referrer-Policy strict-origin-when-cross-origin;
        }
        """
    )

    assert findings == ()


def test_finding_uses_referrer_policy_directive_location() -> None:
    findings = evaluate(
        """server {
    listen 443 ssl;
    add_header Referrer-Policy strict-origin-when-cross-origin;
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
            add_header Referrer-Policy strict-origin-when-cross-origin;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH