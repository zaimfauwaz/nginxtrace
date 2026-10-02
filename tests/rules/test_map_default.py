from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.map_default import MapMissingDefaultRule


def test_rule_reports_map_without_default() -> None:
    directives = parse(
        "map $http_x_role $is_admin {\n"
        "    admin 1;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = MapMissingDefaultRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-MAP-001"
    assert findings[0].line == 1
    assert findings[0].evidence == ("map $http_x_role $is_admin {",)


def test_rule_ignores_map_with_default() -> None:
    directives = parse(
        "map $http_x_role $is_admin {\n"
        "    default 0;\n"
        "    admin 1;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert MapMissingDefaultRule().evaluate(directives) == ()


def test_rule_ignores_config_without_map() -> None:
    directives = parse("listen 80;", Path("nginx.conf"))

    assert MapMissingDefaultRule().evaluate(directives) == ()
