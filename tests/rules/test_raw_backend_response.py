from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.raw_backend_response import RawBackendResponseRule


def test_rule_reports_hide_header_with_intercept_errors() -> None:
    directives = parse(
        "location / {\n"
        "    proxy_pass http://backend;\n"
        "    proxy_intercept_errors on;\n"
        "    proxy_hide_header X-Secret-Token;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = RawBackendResponseRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-PROXY-ERR-001"
    assert findings[0].line == 4
    assert findings[0].evidence == ("proxy_hide_header X-Secret-Token;",)


def test_rule_ignores_intercept_errors_off() -> None:
    directives = parse(
        "location / {\n"
        "    proxy_intercept_errors off;\n"
        "    proxy_hide_header X-Secret-Token;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert RawBackendResponseRule().evaluate(directives) == ()


def test_rule_ignores_hide_header_without_intercept_errors() -> None:
    directives = parse(
        "location / {\n"
        "    proxy_hide_header X-Secret-Token;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert RawBackendResponseRule().evaluate(directives) == ()
