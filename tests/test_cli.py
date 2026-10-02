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
    assert "Potential sensitive dotfile exposure" not in captured.out
    assert "A root directive was found" in captured.out
    assert f"File: {config_file.as_posix()}:2" in captured.out
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
    assert "Error: Configuration file does not exist:" in captured.out
    assert captured.err == ""