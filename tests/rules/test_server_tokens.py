from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.server_tokens import ServerTokensEnabledRule


def test_server_tokens_on_reports_finding() -> None:
    directives = parse(
        "http {\n"
        "    server_tokens on;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = ServerTokensEnabledRule().evaluate(directives)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "NGX-INFO-001"
    assert finding.severity.value == "low"
    assert finding.confidence.value == "high"
    assert finding.file == Path("nginx.conf")
    assert finding.line == 2
    assert finding.message == "server_tokens is explicitly enabled."
    assert finding.evidence == ("server_tokens on;",)


def test_server_tokens_off_does_not_report_finding() -> None:
    directives = parse(
        "http {\n"
        "    server_tokens off;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = ServerTokensEnabledRule().evaluate(directives)

    assert findings == ()


def test_missing_server_tokens_does_not_report_finding() -> None:
    directives = parse(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = ServerTokensEnabledRule().evaluate(directives)

    assert findings == ()


def test_server_tokens_on_in_included_file_reports_its_source_location() -> None:
    directives = parse(
        "server_tokens on;\n",
        Path("conf.d/security.conf"),
    )

    findings = ServerTokensEnabledRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].file == Path("conf.d/security.conf")
    assert findings[0].line == 1