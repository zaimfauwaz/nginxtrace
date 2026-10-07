from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.permissions_policy_without_always import (
    PermissionsPolicyWithoutAlwaysRule,
)


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return PermissionsPolicyWithoutAlwaysRule().evaluate(directives)


def test_does_not_report_when_permissions_policy_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_baseline_features_are_not_all_disabled() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "camera=(), microphone=*";
        }
        """
    )

    assert findings == ()


def test_does_not_report_invalid_policy_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "camera=(self)";
        }
        """
    )

    assert findings == ()


def test_reports_baseline_policy_without_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy
                "camera=(), microphone=(), geolocation=()";
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-018"
    assert "always" in findings[0].message


def test_does_not_report_baseline_policy_with_always() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy
                "camera=(), microphone=(), geolocation=()" always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header Permissions-Policy
                "camera=(), microphone=(), geolocation=()";
        }
        """
    )

    assert findings == ()


def test_finding_uses_permissions_policy_directive_location() -> None:
    findings = evaluate(
        """server {
    listen 443 ssl;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()";
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
            add_header Permissions-Policy
                "camera=(), microphone=(), geolocation=()";
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH