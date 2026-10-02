from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.header_multiline import MultilineHeaderRule


def test_rule_reports_multiline_header_value() -> None:
    directives = parse(
        'add_header Content-Security-Policy "\n'
        "    default-src 'self';\n"
        '";\n',
        Path("nginx.conf"),
    )

    findings = MultilineHeaderRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-HEADER-ML-001"
    assert findings[0].line == 1
    assert "\n" not in findings[0].evidence[0]


def test_rule_ignores_single_line_header_value() -> None:
    directives = parse("add_header X-Frame-Options DENY;", Path("nginx.conf"))

    assert MultilineHeaderRule().evaluate(directives) == ()


def test_rule_ignores_config_without_add_header() -> None:
    directives = parse("listen 80;", Path("nginx.conf"))

    assert MultilineHeaderRule().evaluate(directives) == ()
