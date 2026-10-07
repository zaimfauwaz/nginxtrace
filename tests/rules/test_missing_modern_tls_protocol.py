from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.missing_modern_tls_protocol import (
    MissingModernTlsProtocolRule,
)


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return MissingModernTlsProtocolRule().evaluate(directives)


def test_does_not_report_when_ssl_protocols_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_when_tlsv1_2_is_enabled() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1.2;
        """
    )

    assert findings == ()


def test_does_not_report_when_tlsv1_3_is_enabled() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1.3;
        """
    )

    assert findings == ()


def test_does_not_report_when_both_modern_protocols_are_enabled() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1.2 TLSv1.3;
        """
    )

    assert findings == ()


def test_does_not_duplicate_legacy_tls_finding_for_tlsv1() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1 TLSv1.1;
        """
    )

    assert findings == ()


def test_does_not_duplicate_legacy_tls_finding_for_ssl_protocols() -> None:
    findings = evaluate(
        """
        ssl_protocols SSLv2 SSLv3;
        """
    )

    assert findings == ()


def test_reports_unknown_only_ssl_protocols() -> None:
    findings = evaluate(
        """
        ssl_protocols UNKNOWN;
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-TLS-002"
    assert "TLSv1.2 or TLSv1.3" in findings[0].message


def test_reports_ssl_protocols_without_arguments() -> None:
    findings = evaluate(
        """
        ssl_protocols;
        """
    )

    assert len(findings) == 1


def test_reports_nested_unknown_only_ssl_protocols() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            ssl_protocols UNKNOWN;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].line == 4


def test_uses_medium_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        ssl_protocols UNKNOWN;
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.HIGH