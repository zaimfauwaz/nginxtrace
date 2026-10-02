from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.merge_slashes import MergeSlashesOffRule


def test_rule_reports_merge_slashes_off() -> None:
    directives = parse(
        "http {\n"
        "    merge_slashes off;\n"
        "}\n",
        Path("nginx.conf"),
    )

    findings = MergeSlashesOffRule().evaluate(directives)

    assert len(findings) == 1
    assert findings[0].rule_id == "NGX-SLASH-001"
    assert findings[0].line == 2
    assert findings[0].evidence == ("merge_slashes off;",)


def test_rule_ignores_merge_slashes_on() -> None:
    directives = parse("merge_slashes on;", Path("nginx.conf"))

    assert MergeSlashesOffRule().evaluate(directives) == ()


def test_rule_ignores_config_without_merge_slashes() -> None:
    directives = parse("listen 80;", Path("nginx.conf"))

    assert MergeSlashesOffRule().evaluate(directives) == ()
