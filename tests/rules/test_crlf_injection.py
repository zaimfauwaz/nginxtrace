from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.crlf_injection import CrlfInjectionRule


def test_rule_reports_return_with_uri() -> None:
    directives = parse(
        "location / {\n"
        "    return 302 https://example.test$uri;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = CrlfInjectionRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-CRLF-001"
    assert findings[0].line == 2
    assert findings[0].evidence == ("return 302 https://example.test$uri;",)


def test_rule_reports_add_header_with_document_uri() -> None:
    directives = parse('add_header X-Path "$document_uri";', Path("nginx.conf"))

    assert len(CrlfInjectionRule().evaluate(directives)) == 1


def test_rule_reports_braced_uri_variable_in_quoted_argument() -> None:
    directives = parse('proxy_pass "http://backend${uri}";', Path("nginx.conf"))

    assert len(CrlfInjectionRule().evaluate(directives)) == 1


def test_rule_ignores_request_uri() -> None:
    directives = parse("return 302 https://example.test$request_uri;", Path("nginx.conf"))

    assert CrlfInjectionRule().evaluate(directives) == ()


def test_rule_ignores_longer_variable_name_starting_with_uri() -> None:
    directives = parse("return 302 https://example.test$uri_prefix;", Path("nginx.conf"))

    assert CrlfInjectionRule().evaluate(directives) == ()


def test_rule_ignores_uri_in_unchecked_directive() -> None:
    directives = parse("try_files $uri $uri/ =404;", Path("nginx.conf"))

    assert CrlfInjectionRule().evaluate(directives) == ()
