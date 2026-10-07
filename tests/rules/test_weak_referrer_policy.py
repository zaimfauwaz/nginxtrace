from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.weak_referrer_policy import WeakReferrerPolicyRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return WeakReferrerPolicyRule().evaluate(directives)


def test_does_not_report_when_referrer_policy_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_no_referrer() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy no-referrer always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_same_origin() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy same-origin always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_strict_origin() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy strict-origin always;
        }
        """
    )

    assert findings == ()


def test_does_not_report_strict_origin_when_cross_origin() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy strict-origin-when-cross-origin always;
        }
        """
    )

    assert findings == ()


def test_reports_origin_policy() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy origin;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-SEC-012"
    assert "unsafe, overly permissive, or invalid" in findings[0].message


def test_reports_origin_when_cross_origin_policy() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy origin-when-cross-origin;
        }
        """
    )

    assert len(findings) == 1


def test_reports_no_referrer_when_downgrade_policy() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy no-referrer-when-downgrade;
        }
        """
    )

    assert len(findings) == 1


def test_reports_unsafe_url_policy() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy unsafe-url;
        }
        """
    )

    assert len(findings) == 1


def test_reports_empty_policy_value() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy "";
        }
        """
    )

    assert len(findings) == 1


def test_reports_unknown_policy_value() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy unknown-policy;
        }
        """
    )

    assert len(findings) == 1


def test_reports_only_non_recommended_header_when_multiple_exist() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy strict-origin-when-cross-origin;
            add_header Referrer-Policy unsafe-url;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].line == 5


def test_does_not_report_http_only_server() -> None:
    findings = evaluate(
        """
        server {
            listen 80;
            add_header Referrer-Policy unsafe-url;
        }
        """
    )

    assert findings == ()


def test_uses_low_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            add_header Referrer-Policy unsafe-url;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.HIGH