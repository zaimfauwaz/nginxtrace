import re
from pathlib import Path

import pytest

from nginxtrace.cli import main

EXAMPLES_DIRECTORY = Path(__file__).parent.parent / "examples"
RULE_EXAMPLE_NAME = re.compile(r"^(ngx-[a-z-]+-\d{3})-(.+)\.nginx\.conf$")
pytestmark = pytest.mark.usefixtures("allow_repository")

RULE_EXAMPLES = sorted(
    path
    for path in EXAMPLES_DIRECTORY.glob("ngx-*.nginx.conf")
    if RULE_EXAMPLE_NAME.match(path.name)
)


def scan_example(
        example: Path,
        capsys: pytest.CaptureFixture[str],
) -> tuple[int, str]:
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--config", str(example)])

    return exit_info.value.code, capsys.readouterr().out


def test_rule_examples_exist() -> None:
    assert RULE_EXAMPLES


@pytest.mark.parametrize("example", RULE_EXAMPLES, ids=lambda path: path.name)
def test_rule_example_matches_its_name(
        example: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    rule_slug, variant = RULE_EXAMPLE_NAME.match(example.name).groups()
    rule_id = rule_slug.upper()

    code, out = scan_example(example, capsys)

    if variant.startswith("safe"):
        assert code in (0, 1)
        assert rule_id not in out
    else:
        assert code == 1
        assert rule_id in out


@pytest.mark.parametrize(
    ("name", "expected_code"),
    (
        ("simple.nginx.conf", 0),
        ("enforce.nginx.conf", 0),
        ("exploit.nginx.conf", 1),
    ),
)
def test_general_examples_return_expected_exit_code(
        name: str,
        expected_code: int,
        capsys: pytest.CaptureFixture[str],
) -> None:
    code, _ = scan_example(EXAMPLES_DIRECTORY / name, capsys)

    assert code == expected_code


INCLUDE_EXAMPLE = EXAMPLES_DIRECTORY / "includes" / "nginx.conf"


def test_include_example_reports_finding_in_included_file(
        capsys: pytest.CaptureFixture[str],
) -> None:
    code, out = scan_example(INCLUDE_EXAMPLE, capsys)

    assert code == 1
    assert "NGX-SLASH-001" in out
    assert "conf.d/legacy.conf:6" in out
    assert "NGX-SECRET-001" not in out


def test_include_example_without_includes_misses_snippet(
        capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--config", str(INCLUDE_EXAMPLE), "--no-includes"])

    out = capsys.readouterr().out

    assert exit_info.value.code == 1
    assert "NGX-SECRET-001" in out
    assert "NGX-SLASH-001" not in out


def test_include_example_dump_matches_config(
        capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--dump", str(EXAMPLES_DIRECTORY / "includes" / "nginx-T.txt")])

    out = capsys.readouterr().out

    assert exit_info.value.code == 1
    assert "File: /etc/nginx/conf.d/legacy.conf:5" in out
    assert "NGX-SECRET-001" not in out
