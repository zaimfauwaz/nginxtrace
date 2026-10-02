from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.header_redefinition import HeaderRedefinitionRule


def test_rule_reports_nested_add_header() -> None:
    directives = parse(
        "server {\n"
        "    add_header X-Frame-Options DENY;\n"
        "\n"
        "    location / {\n"
        "        add_header X-Cache HIT;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = HeaderRedefinitionRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-001"
    assert findings[0].line == 5
    assert findings[0].evidence == (
        "location / {",
        "add_header X-Cache HIT;",
    )


def test_rule_ignores_add_header_only_in_parent() -> None:
    directives = parse(
        "server {\n"
        "    add_header X-Frame-Options DENY;\n"
        "\n"
        "    location / {\n"
        "        root /var/www/app/public;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert HeaderRedefinitionRule().evaluate(directives) == ()


def test_rule_ignores_add_header_only_in_child() -> None:
    directives = parse(
        "server {\n"
        "    location / {\n"
        "        add_header X-Cache HIT;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert HeaderRedefinitionRule().evaluate(directives) == ()
