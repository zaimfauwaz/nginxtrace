import os
from pathlib import Path

import pytest

from nginxtrace.config import includes
from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.parser import ParseError
from nginxtrace.config.service import parse_file
from nginxtrace.rules.helpers import find_directives


def write(tmp_path: Path, name: str, text: str) -> Path:
    file = tmp_path / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8")
    return file


def test_include_is_replaced_inside_block(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "server {\n    include deny.conf;\n}\n")
    write(tmp_path, "deny.conf", "location ~ /\\. {\n    deny all;\n}\n")

    directives = parse_file(main_file)

    server = directives[0]
    assert [child.name for child in server.children] == ["location"]
    assert server.children[0].file == tmp_path / "deny.conf"
    assert server.children[0].line == 1


def test_included_directives_keep_their_own_file_and_line(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include app.conf;\nlisten 80;\n")
    write(tmp_path, "app.conf", "\n\nroot /var/www;\n")

    directives = parse_file(main_file)

    assert [(d.name, d.file.name, d.line) for d in directives] == [
        ("root", "app.conf", 3),
        ("listen", "nginx.conf", 2),
    ]


def test_wildcard_include_is_sorted(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include conf.d/*.conf;\n")
    write(tmp_path, "conf.d/b.conf", "listen 81;\n")
    write(tmp_path, "conf.d/a.conf", "listen 80;\n")
    write(tmp_path, "conf.d/notes.txt", "not nginx\n")

    directives = parse_file(main_file)

    assert [d.arguments for d in directives] == [("80",), ("81",)]


def test_wildcard_include_without_matches_is_allowed(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include conf.d/*.conf;\nlisten 80;\n")

    directives = parse_file(main_file)

    assert [d.name for d in directives] == ["listen"]


def test_wildcard_does_not_match_hidden_files(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include conf.d/*;\n")
    write(tmp_path, "conf.d/.hidden.conf", "listen 81;\n")
    write(tmp_path, "conf.d/app.conf", "listen 80;\n")

    directives = parse_file(main_file)

    assert [d.arguments for d in directives] == [("80",)]


def test_nested_include_is_relative_to_main_config_directory(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include conf.d/app.conf;\n")
    write(tmp_path, "conf.d/app.conf", "include snippets/deny.conf;\n")
    write(tmp_path, "snippets/deny.conf", "deny all;\n")

    directives = parse_file(main_file)

    assert directives[0].file == tmp_path / "snippets" / "deny.conf"


def test_absolute_include_inside_base_dir(tmp_path: Path) -> None:
    included = write(tmp_path, "abs.conf", "listen 80;\n")
    main_file = write(tmp_path, "nginx.conf", f'include "{included.as_posix()}";\n')

    directives = parse_file(main_file)

    assert directives[0].file == included


def test_missing_literal_include_is_an_error(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "listen 80;\ninclude missing.conf;\n")

    with pytest.raises(ConfigLoadError, match=r"does not exist.*included from .*nginx.conf:2"):
        parse_file(main_file)


def test_include_needs_exactly_one_argument(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include a.conf b.conf;\n")

    with pytest.raises(ConfigLoadError, match=r"include expects exactly one argument"):
        parse_file(main_file)


def test_include_of_itself_is_a_cycle(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include nginx.conf;\n")

    with pytest.raises(ConfigLoadError, match=r"Include cycle detected"):
        parse_file(main_file)


def test_indirect_include_cycle_is_detected(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include a.conf;\n")
    write(tmp_path, "a.conf", "include b.conf;\n")
    write(tmp_path, "b.conf", "include a.conf;\n")

    with pytest.raises(ConfigLoadError, match=r"Include cycle detected: .*a.conf -> .*b.conf -> .*a.conf"):
        parse_file(main_file)


def test_same_file_included_twice_is_not_a_cycle(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include a.conf;\ninclude a.conf;\n")
    write(tmp_path, "a.conf", "listen 80;\n")

    directives = parse_file(main_file)

    assert len(directives) == 2


def test_too_many_included_files_is_an_error(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(includes, "MAX_INCLUDED_FILES", 2)
    main_file = write(tmp_path, "nginx.conf", "include a.conf;\ninclude a.conf;\ninclude a.conf;\n")
    write(tmp_path, "a.conf", "listen 80;\n")

    with pytest.raises(ConfigLoadError, match=r"More than 2 included files"):
        parse_file(main_file)


def test_deeply_nested_includes_are_an_error(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include level-1.conf;\n")
    for level in range(1, 40):
        write(tmp_path, f"level-{level}.conf", f"include level-{level + 1}.conf;\n")
    write(tmp_path, "level-40.conf", "listen 80;\n")

    with pytest.raises(ConfigLoadError, match=r"nested more than 32 levels deep"):
        parse_file(main_file)


def test_nesting_across_included_files_is_limited(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "a {" * 30 + "include inner.conf;" + "}" * 30)
    write(tmp_path, "inner.conf", "b {" * 30 + "}" * 30)

    with pytest.raises(ConfigLoadError, match=r"nested more than 50 levels deep across included files"):
        parse_file(main_file)


def test_parse_error_in_included_file_names_the_file(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include broken.conf;\n")
    write(tmp_path, "broken.conf", "listen 80\n")

    with pytest.raises(ParseError, match=r"broken.conf: Expected ';' or '\{'"):
        parse_file(main_file)


def test_wildcard_in_directory_is_rejected(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include sites/*/app.conf;\n")

    with pytest.raises(ConfigLoadError, match=r"Wildcards are only supported in the file name"):
        parse_file(main_file)


def test_no_includes_keeps_include_directive(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include missing.conf;\n")

    directives = parse_file(main_file, resolve_includes=False)

    assert [(d.name, d.arguments) for d in directives] == [("include", ("missing.conf",))]


def test_include_does_not_change_find_directives_results(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "http {\n    include servers.conf;\n}\n")
    write(tmp_path, "servers.conf", "server {\n    root /a;\n}\nserver {\n    root /b;\n}\n")

    roots = find_directives(parse_file(main_file), "root")

    assert [root.arguments for root in roots] == [("/a",), ("/b",)]


# Security: included files must stay inside the allowed base directory.

def test_literal_include_outside_base_dir_is_rejected(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include ../outside.conf;\n")
    (tmp_path.parent / "outside.conf").write_text("listen 80;\n", encoding="utf-8")

    with pytest.raises(ConfigLoadError, match=r"Path is outside the allowed directory"):
        parse_file(main_file)


def test_absolute_include_outside_base_dir_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.conf"
    outside.write_text("listen 80;\n", encoding="utf-8")
    main_file = write(tmp_path, "nginx.conf", f'include "{outside.as_posix()}";\n')

    with pytest.raises(ConfigLoadError, match=r"Path is outside the allowed directory"):
        parse_file(main_file)


def test_wildcard_directory_outside_base_dir_is_rejected(tmp_path: Path) -> None:
    main_file = write(tmp_path, "nginx.conf", "include ../*.conf;\n")

    with pytest.raises(ConfigLoadError, match=r"Path is outside the allowed directory"):
        parse_file(main_file)


def test_wildcard_match_symlinked_outside_base_dir_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.conf"
    outside.write_text("listen 80;\n", encoding="utf-8")
    main_file = write(tmp_path, "nginx.conf", "include conf.d/*.conf;\n")
    (tmp_path / "conf.d").mkdir()

    try:
        (tmp_path / "conf.d" / "escape.conf").symlink_to(outside)
    except OSError as err:
        if os.name == "nt" and getattr(err, "winerror", None) == 1314:
            pytest.skip("Creating symlinks requires Windows Developer Mode or elevation")
        raise

    with pytest.raises(ConfigLoadError, match=r"Path is outside the allowed directory"):
        parse_file(main_file)

def test_unterminated_quote_in_included_file_names_the_file(
        tmp_path: Path,
) -> None:
    main_file = write(tmp_path, "nginx.conf", "include broken.conf;\n")
    write(tmp_path, "broken.conf", 'add_header X-Test "unterminated;\n')

    with pytest.raises(
            ParseError,
            match=(
                    r"broken\.conf: Unterminated quoted string "
                    r"starting on line 1"
            ),
    ):
        parse_file(main_file)


def test_structural_error_in_included_file_names_the_file(
        tmp_path: Path,
) -> None:
    main_file = write(tmp_path, "nginx.conf", "include broken.conf;\n")
    write(tmp_path, "broken.conf", "server {\n")

    with pytest.raises(
            ParseError,
            match=r"broken\.conf: Expected '\}' to close directive 'server'",
    ):
        parse_file(main_file)


def test_nested_included_file_error_names_the_deepest_file(
        tmp_path: Path,
) -> None:
    main_file = write(tmp_path, "nginx.conf", "include conf.d/app.conf;\n")
    write(tmp_path, "conf.d/app.conf", "include snippets/broken.conf;\n")
    write(tmp_path, "snippets/broken.conf", "listen 80;;\n")

    with pytest.raises(
            ParseError,
            match=r"broken\.conf: Unexpected token ';' on line 1",
    ):
        parse_file(main_file)


def test_malformed_wildcard_match_names_the_matching_file(
        tmp_path: Path,
) -> None:
    main_file = write(tmp_path, "nginx.conf", "include conf.d/*.conf;\n")
    write(tmp_path, "conf.d/valid.conf", "listen 80;\n")
    write(tmp_path, "conf.d/broken.conf", "location /api {\n")

    with pytest.raises(
            ParseError,
            match=r"broken\.conf: Expected '\}' to close directive 'location'",
    ):
        parse_file(main_file)


def test_no_includes_does_not_parse_malformed_included_file(
        tmp_path: Path,
) -> None:
    main_file = write(tmp_path, "nginx.conf", "include broken.conf;\n")
    write(tmp_path, "broken.conf", 'add_header X-Test "unterminated;\n')

    directives = parse_file(main_file, resolve_includes=False)

    assert [(directive.name, directive.arguments) for directive in directives] == [
        ("include", ("broken.conf",)),
    ]