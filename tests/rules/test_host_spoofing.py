from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.host_spoofing import HostSpoofingRule


def test_rule_reports_host_from_http_host() -> None:
    directives = parse(
        "location / {\n"
        "    proxy_set_header Host $http_host;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = HostSpoofingRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HOST-001"
    assert findings[0].line == 2
    assert findings[0].evidence == ("proxy_set_header Host $http_host;",)


def test_rule_matches_header_name_case_insensitively() -> None:
    directives = parse("proxy_set_header host $http_host;", Path("nginx.conf"))

    assert len(HostSpoofingRule().evaluate(directives)) == 1


def test_rule_ignores_host_from_host_variable() -> None:
    directives = parse("proxy_set_header Host $host;", Path("nginx.conf"))

    assert HostSpoofingRule().evaluate(directives) == ()


def test_rule_ignores_other_headers() -> None:
    directives = parse("proxy_set_header X-Original-Host $http_host;", Path("nginx.conf"))

    assert HostSpoofingRule().evaluate(directives) == ()
