from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.legacy_tls_protocol import LegacyTlsProtocolRule


def evaluate(config: str):
    directives = parse(config, Path("nginx.conf"))
    return LegacyTlsProtocolRule().evaluate(directives)


def test_does_not_report_when_ssl_protocols_is_absent() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
        }
        """
    )

    assert findings == ()


def test_does_not_report_modern_tls_protocols() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1.2 TLSv1.3;
        """
    )

    assert findings == ()


def test_reports_tlsv1() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1 TLSv1.2 TLSv1.3;
        """
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-TLS-001"
    assert "TLSv1" in findings[0].message


def test_reports_tlsv1_1() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1.1 TLSv1.2;
        """
    )

    assert len(findings) == 1
    assert "TLSv1.1" in findings[0].message


def test_reports_legacy_ssl_protocols() -> None:
    findings = evaluate(
        """
        ssl_protocols SSLv2 SSLv3 TLSv1.2;
        """
    )

    assert len(findings) == 1
    assert "SSLv2, SSLv3" in findings[0].message


def test_reports_all_legacy_protocols_in_stable_order() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1.1 SSLv3 TLSv1 SSLv2 TLSv1.2;
        """
    )

    assert len(findings) == 1
    assert (
            findings[0].message
            == "ssl_protocols explicitly enables legacy protocol(s): "
               "SSLv2, SSLv3, TLSv1, TLSv1.1."
    )


def test_reports_nested_ssl_protocols_directive() -> None:
    findings = evaluate(
        """
        server {
            listen 443 ssl;
            ssl_protocols TLSv1 TLSv1.2;
        }
        """
    )

    assert len(findings) == 1
    assert findings[0].line == 4


def test_ignores_unknown_protocol_tokens() -> None:
    findings = evaluate(
        """
        ssl_protocols UNKNOWN TLSv1.2 TLSv1.3;
        """
    )

    assert findings == ()


def test_uses_medium_severity_and_high_confidence() -> None:
    findings = evaluate(
        """
        ssl_protocols TLSv1 TLSv1.2;
        """
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.HIGH