from pathlib import Path

import pytest

from nginxtrace.config.dump import split_dump
from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.service import parse_dump

DUMP = (
    "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
    "# configuration file /etc/nginx/nginx.conf:\n"
    "http {\n"
    "    include conf.d/*.conf;\n"
    "}\n"
    "\n"
    "# configuration file /etc/nginx/conf.d/app.conf:\n"
    "server {\n"
    "    root /var/www;\n"
    "}\n"
)


def write_dump(tmp_path: Path, text: str) -> Path:
    dump_file = tmp_path / "nginx-T.txt"
    dump_file.write_text(text, encoding="utf-8")
    return dump_file


def test_split_dump_returns_files_in_order() -> None:
    sources = split_dump(DUMP)

    assert list(sources) == [
        Path("/etc/nginx/nginx.conf"),
        Path("/etc/nginx/conf.d/app.conf"),
    ]
    assert sources[Path("/etc/nginx/conf.d/app.conf")] == "server {\n    root /var/www;\n}\n"


def test_split_dump_ignores_lines_before_first_header() -> None:
    sources = split_dump(DUMP)

    assert "syntax is ok" not in sources[Path("/etc/nginx/nginx.conf")]


def test_split_dump_without_headers_is_an_error() -> None:
    with pytest.raises(ConfigLoadError, match=r"No '# configuration file <path>:' sections"):
        split_dump("server {\n}\n")


def test_parse_dump_expands_includes_from_dump(tmp_path: Path) -> None:
    directives = parse_dump(write_dump(tmp_path, DUMP))

    server = directives[0].children[0]
    assert server.name == "server"
    assert server.file == Path("/etc/nginx/conf.d/app.conf")
    assert server.children[0].line == 2


def test_parse_dump_without_includes_keeps_include_directive(tmp_path: Path) -> None:
    directives = parse_dump(write_dump(tmp_path, DUMP), resolve_includes=False)

    assert directives[0].children[0].name == "include"


def test_parse_dump_never_reads_included_files_from_disk(tmp_path: Path) -> None:
    on_disk = tmp_path / "extra.conf"
    on_disk.write_text("listen 80;\n", encoding="utf-8")
    text = f"# configuration file {(tmp_path / 'nginx.conf').as_posix()}:\ninclude extra.conf;\n"

    dump_file = write_dump(tmp_path, text)

    with pytest.raises(ConfigLoadError, match=r"Included file is not in the dump"):
        parse_dump(dump_file)


def test_parse_dump_file_outside_base_dir_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "nginx-T.txt"
    outside.write_text(DUMP, encoding="utf-8")

    with pytest.raises(ConfigLoadError, match=r"Path is outside the allowed directory"):
        parse_dump(outside)
