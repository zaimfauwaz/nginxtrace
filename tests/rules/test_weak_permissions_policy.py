from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.weak_permissions_policy import WeakPermissionsPolicyRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return WeakPermissionsPolicyRule().evaluate(directives)


def test_does_not_report_when_permissions_policy_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_all_baseline_features_are_disabled() -> None:
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


def test_reports_missing_baseline_features() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "camera=()";
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-016"
    assert "microphone, geolocation" in findings[0].message


def test_reports_wildcard_baseline_feature() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy
                "camera=(), microphone=*, geolocation=()";
        }
        """
    )

    assert len(findings) == 1
    assert "microphone" in findings[0].message


def test_reports_unsupported_allowlist_syntax() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "camera=(self)";
        }
        """
    )

    assert len(findings) == 1
    assert "camera, microphone, geolocation" in findings[0].message


def test_reports_empty_policy_value() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "";
        }
        """
    )

    assert len(findings) == 1


def test_reports_duplicate_feature_directive() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "camera=(), camera=*";
        }
        """
    )

    assert len(findings) == 1


def test_reports_each_weak_policy_header() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "camera=()";
            add_header Permissions-Policy "microphone=()";
        }
        """
    )

    assert len(findings) == 2
    assert findings[0].line == 4
    assert findings[1].line == 5


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header Permissions-Policy "camera=*";
        }
        """
    )

    assert findings == ()


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Permissions-Policy "camera=*";
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH