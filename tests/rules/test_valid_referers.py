from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.valid_referers import ValidReferersNoneRule


def test_rule_reports_none_among_referers() -> None:
    directives = parse(
        "location /images/ {\n"
        "    valid_referers none server_names *.example.test;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = ValidReferersNoneRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-REFERER-001"
    assert findings[0].line == 2


def test_rule_ignores_referers_without_none() -> None:
    directives = parse("valid_referers server_names *.example.test;", Path("nginx.conf"))

    assert ValidReferersNoneRule().evaluate(directives) == ()


def test_rule_ignores_config_without_valid_referers() -> None:
    directives = parse("listen 80;", Path("nginx.conf"))

    assert ValidReferersNoneRule().evaluate(directives) == ()
