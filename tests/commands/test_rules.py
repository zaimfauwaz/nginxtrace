import pytest

from nginxtrace.commands.rules import run_list, run_show


def test_run_list_prints_one_line_per_rule(
        capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_list() == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == (
        "NGX-SECRET-001       high     medium   "
        "Potential sensitive dotfile exposure"
    )


def test_run_show_prints_description_and_remediation(
        capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_show("NGX-SLASH-001") == 0

    out = capsys.readouterr().out
    assert out.startswith(
        "Rule: NGX-SLASH-001\n"
        "Title: merge_slashes is disabled\n"
        "Severity: low\n"
        "Confidence: high\n"
    )
    assert "Remediation:\n" in out


def test_run_show_returns_two_for_unknown_rule(
        capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_show("NGX-UNKNOWN-999") == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Error: Unknown rule ID: NGX-UNKNOWN-999\n"
