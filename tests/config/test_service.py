from pathlib import Path

import pytest

from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.parser import ParseError
from nginxtrace.config.service import parse_file


def test_parse_file_returns_parsed_directives(tmp_path: Path) -> None:
    config_file = tmp_path / "nginx.conf"
    config_file.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.test;\n"
        "}\n",
        encoding="utf-8",
    )

    directives = parse_file(config_file)

    assert len(directives) == 1

    server = directives[0]
    assert server.name == "server"
    assert server.arguments == ()
    assert server.file == config_file
    assert server.line == 1
    assert server.children is not None

    assert len(server.children) == 2

    listen = server.children[0]
    assert listen.name == "listen"
    assert listen.arguments == ("80",)
    assert listen.line == 2

    server_name = server.children[1]
    assert server_name.name == "server_name"
    assert server_name.arguments == ("example.test",)
    assert server_name.line == 3


def test_parse_file_raises_config_load_error_for_missing_file(
        tmp_path: Path,
) -> None:
    missing_file = tmp_path / "missing.conf"

    with pytest.raises(
            ConfigLoadError,
            match=r"Configuration file does not exist:",
    ):
        parse_file(missing_file)


def test_parse_file_raises_parse_error_for_invalid_config(
        tmp_path: Path,
) -> None:
    config_file = tmp_path / "invalid.conf"
    config_file.write_text(
        "server {\n"
        "    listen 80;\n",
        encoding="utf-8",
    )

    with pytest.raises(
            ParseError,
            match=r"Expected '\}' to close directive 'server'",
    ):
        parse_file(config_file)