import re
from pathlib import Path

import pytest

from nginxtrace.cli import main

EXAMPLES_DIRECTORY = Path(__file__).parent.parent / "examples"
RULE_EXAMPLE_NAME = re.compile(r"^(ngx-[a-z-]+-\d{3})-(.+)\.nginx\.conf$")
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
