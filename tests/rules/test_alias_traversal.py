from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.alias_traversal import AliasTraversalRule


def test_rule_reports_off_by_slash_alias() -> None:
    directives = parse(
        "server {\n"
        "    location /files {\n"
        "        alias /srv/files/;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = AliasTraversalRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-ALIAS-001"
    assert findings[0].line == 2
    assert findings[0].evidence == (
        "location /files {",
        "alias /srv/files/;",
    )


def test_rule_ignores_matching_trailing_slashes() -> None:
    directives = parse(
        "location /files/ {\n"
        "    alias /srv/files/;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert AliasTraversalRule().evaluate(directives) == ()


def test_rule_ignores_alias_without_trailing_slash() -> None:
    directives = parse(
        "location /files {\n"
        "    alias /srv/files;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert AliasTraversalRule().evaluate(directives) == ()


def test_rule_ignores_regex_location() -> None:
    directives = parse(
        "location ~ ^/files/(.+)$ {\n"
        "    alias /srv/files/$1;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert AliasTraversalRule().evaluate(directives) == ()


def test_rule_checks_path_after_prefix_modifier() -> None:
    directives = parse(
        "location ^~ /files {\n"
        "    alias /srv/files/;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert len(AliasTraversalRule().evaluate(directives)) == 1
