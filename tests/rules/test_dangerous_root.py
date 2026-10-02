from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.dangerous_root import DangerousRootRule


def test_rule_reports_root_set_to_filesystem_root() -> None:
    directives = parse(
        "server {\n"
        "    root /;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = DangerousRootRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-ROOT-001"
    assert findings[0].line == 2
    assert findings[0].evidence == ("root /;",)


def test_rule_reports_root_set_to_etc() -> None:
    directives = parse("root /etc/;", Path("nginx.conf"))

    findings = DangerousRootRule().evaluate(directives)

    assert len(findings) == 1


def test_rule_ignores_application_root() -> None:
    directives = parse("root /var/www/app/public;", Path("nginx.conf"))

    assert DangerousRootRule().evaluate(directives) == ()


def test_rule_ignores_config_without_root() -> None:
    directives = parse("listen 80;", Path("nginx.conf"))

    assert DangerousRootRule().evaluate(directives) == ()
