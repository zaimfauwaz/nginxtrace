from pathlib import Path

import pytest

from nginxtrace.config.loader import ConfigLoadError, load_file


def test_load_file_returns_file_text(tmp_path: Path) -> None:
    config_file = tmp_path / "nginx.conf"
    config_text = "server {\n    listen 80;\n}\n"

    config_file.write_text(config_text, encoding="utf-8")

    result = load_file(config_file)

    assert result == config_text


def test_load_file_rejects_missing_file(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.conf"

    with pytest.raises(
            ConfigLoadError,
            match=r"Configuration file does not exist:",
    ):
        load_file(missing_file)


def test_load_file_rejects_directory(tmp_path: Path) -> None:
    config_directory = tmp_path / "conf.d"
    config_directory.mkdir()

    with pytest.raises(
            ConfigLoadError,
            match=r"Configuration file is not a file:",
    ):
        load_file(config_directory)

def test_load_file_rejects_path_outside_base_dir(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside_file = tmp_path / "secret.conf"
    outside_file.write_text("listen 80;\n", encoding="utf-8")
    monkeypatch.setenv("NGINXTRACE_BASE_DIR", str(allowed))

    with pytest.raises(
            ConfigLoadError,
            match=r"Path is outside the allowed directory",
    ):
        load_file(outside_file)
