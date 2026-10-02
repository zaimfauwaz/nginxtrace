import json
import runpy
import sys
from pathlib import Path

import pytest

from nginxtrace.cli import main


def test_cli_scan_returns_zero_for_safe_config(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = tmp_path / "safe.conf"
    config_file.write_text(
        "server {\n"
        "    listen 80;\n"
        "}\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                "scan",
                "--config",
                str(config_file),
            ]
        )

    captured = capsys.readouterr()

    assert exit_info.value.code == 0
    assert captured.out == "No findings.\n"
    assert captured.err == ""


def test_cli_scan_returns_one_for_unsafe_config(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = tmp_path / "unsafe.conf"
    config_file.write_text(
        "server {\n"
        "    root /var/www/app/public;\n"
        "}\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                "scan",
                "--config",
                str(config_file),
            ]
        )

    captured = capsys.readouterr()

    assert exit_info.value.code == 1
    assert "HIGH     NGX-SECRET-001" in captured.out
    assert "Potential sensitive dotfile exposure" in captured.out
    assert "A root directive was found" in captured.out
    assert f"File: {config_file.as_posix()}:2" in captured.out
    assert "Confidence: medium" in captured.out
    assert "Remediation:" in captured.out
    assert "Evidence:\nroot /var/www/app/public;" in captured.out
    assert captured.err == ""


def test_cli_scan_returns_two_for_missing_config(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    missing_file = tmp_path / "missing.conf"

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                "scan",
                "--config",
                str(missing_file),
            ]
        )

    captured = capsys.readouterr()

    assert exit_info.value.code == 2
    assert captured.out == ""
    assert "Error: Configuration file does not exist:" in captured.err


def run_cli(
        arguments: list[str],
        capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    with pytest.raises(SystemExit) as exit_info:
        main(arguments)

    captured = capsys.readouterr()
    return exit_info.value.code, captured.out, captured.err


def write_config(tmp_path: Path, text: str) -> Path:
    config_file = tmp_path / "nginx.conf"
    config_file.write_text(text, encoding="utf-8")
    return config_file


def test_cli_scan_returns_two_for_unterminated_quote(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, 'add_header X-Test "missing quote;\n')

    code, out, err = run_cli(["scan", "--config", str(config_file)], capsys)

    assert code == 2
    assert out == ""
    assert "Error: Unterminated quoted string starting on line 1" in err


def test_cli_scan_min_severity_hides_lower_findings(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "merge_slashes off;\n")

    code, out, _ = run_cli(
        ["scan", "--config", str(config_file), "--min-severity", "high"],
        capsys,
    )

    assert code == 0
    assert out == "No findings.\n"


def test_cli_scan_min_severity_keeps_matching_findings(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "merge_slashes off;\n")

    code, out, _ = run_cli(
        ["scan", "--config", str(config_file), "--min-severity", "low"],
        capsys,
    )

    assert code == 1
    assert "NGX-SLASH-001" in out


def test_cli_scan_rejects_unknown_min_severity(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "listen 80;\n")

    code, _, err = run_cli(
        ["scan", "--config", str(config_file), "--min-severity", "urgent"],
        capsys,
    )

    assert code == 2
    assert "invalid Severity value" in err


def test_cli_scan_prints_summary_line(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "server {\n    root /var/www/app/public;\n}\n")

    _, out, _ = run_cli(["scan", "--config", str(config_file)], capsys)

    assert out.endswith("1 finding (1 high)\n")


def test_cli_scan_json_output(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "server {\n    root /var/www/app/public;\n}\n")

    code, out, err = run_cli(
        ["scan", "--config", str(config_file), "--format", "json"],
        capsys,
    )

    result = json.loads(out)
    assert code == 1
    assert err == ""
    assert result["total"] == 1
    assert result["findings"][0]["rule_id"] == "NGX-SECRET-001"
    assert result["findings"][0]["line"] == 2


def test_cli_scan_json_output_without_findings(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "listen 80;\n")

    code, out, _ = run_cli(
        ["scan", "--config", str(config_file), "--format", "json"],
        capsys,
    )

    assert code == 0
    assert json.loads(out) == {"total": 0, "findings": []}


def test_cli_check_returns_zero_for_valid_syntax(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "server {\n    root /var/www/app/public;\n}\n")

    code, out, err = run_cli(["check", "--config", str(config_file)], capsys)

    assert code == 0
    assert out == f"Syntax OK: {config_file.as_posix()}\n"
    assert err == ""


def test_cli_check_returns_two_for_invalid_syntax(
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = write_config(tmp_path, "server {\n    listen 80;\n")

    code, out, err = run_cli(["check", "--config", str(config_file)], capsys)

    assert code == 2
    assert out == ""
    assert "Error: Expected '}' to close directive 'server'" in err


def test_cli_rules_list_prints_every_rule(
        capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run_cli(["rules", "list"], capsys)

    assert code == 0
    assert len(out.splitlines()) == 12
    assert out.startswith("NGX-SECRET-001")


def test_cli_rules_show_prints_rule_metadata(
        capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run_cli(["rules", "show", "NGX-ALIAS-001"], capsys)

    assert code == 0
    assert "Rule: NGX-ALIAS-001" in out
    assert "Severity: high" in out
    assert "Remediation:" in out


def test_cli_rules_show_returns_two_for_unknown_rule(
        capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, err = run_cli(["rules", "show", "NGX-UNKNOWN-999"], capsys)

    assert code == 2
    assert out == ""
    assert "Error: Unknown rule ID: NGX-UNKNOWN-999" in err


def test_python_module_entry_point_runs_cli(
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["nginxtrace", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("nginxtrace", run_name="__main__")

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("nginxtrace ")
