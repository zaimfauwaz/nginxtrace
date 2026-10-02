from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.ssrf import SsrfRule


def test_rule_reports_variable_proxy_host() -> None:
    directives = parse(
        "location ~ /proxy/(.*)$ {\n"
        "    proxy_pass http://$1;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = SsrfRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-SSRF-001"
    assert findings[0].line == 2
    assert findings[0].evidence == (
        "location ~ /proxy/(.*)$ {",
        "proxy_pass http://$1;",
    )


def test_rule_reports_proxy_pass_that_is_only_a_variable() -> None:
    directives = parse(
        "location / {\n"
        "    proxy_pass $target;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert len(SsrfRule().evaluate(directives)) == 1


def test_rule_ignores_variable_in_path_only() -> None:
    directives = parse(
        "location / {\n"
        "    proxy_pass http://backend$request_uri;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert SsrfRule().evaluate(directives) == ()


def test_rule_ignores_internal_location() -> None:
    directives = parse(
        "location /internal-proxy/ {\n"
        "    internal;\n"
        "    proxy_pass http://$upstream_host;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert SsrfRule().evaluate(directives) == ()


def test_rule_ignores_fixed_proxy_host() -> None:
    directives = parse(
        "location / {\n"
        "    proxy_pass http://backend;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert SsrfRule().evaluate(directives) == ()
