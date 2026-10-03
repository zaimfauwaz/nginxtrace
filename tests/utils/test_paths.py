import os
from pathlib import Path

import pytest

from nginxtrace.utils.paths import (
    BASE_DIR_VARIABLE,
    UnsafePathError,
    allowed_base_dir,
    resolve_within,
)


def test_resolve_within_accepts_file_inside_base(tmp_path: Path) -> None:
    config_file = tmp_path / "nginx.conf"
    config_file.write_text("", encoding="utf-8")

    assert resolve_within(config_file, tmp_path) == Path(os.path.realpath(config_file))


def test_resolve_within_accepts_relative_path_inside_base(tmp_path: Path) -> None:
    (tmp_path / "conf.d").mkdir()

    result = resolve_within(Path("conf.d/app.conf"), tmp_path)

    assert result == Path(os.path.realpath(tmp_path / "conf.d" / "app.conf"))


def test_resolve_within_rejects_parent_traversal(tmp_path: Path) -> None:
    base = tmp_path / "allowed"
    base.mkdir()
    escape = Path("..") / "secret.conf"

    with pytest.raises(UnsafePathError, match=r"outside the allowed directory"):
        resolve_within(escape, base)


def test_resolve_within_rejects_absolute_path_outside_base(tmp_path: Path) -> None:
    base = tmp_path / "allowed"
    base.mkdir()
    outside = tmp_path / "secret.conf"

    with pytest.raises(UnsafePathError, match=r"outside the allowed directory"):
        resolve_within(outside, base)


def test_resolve_within_rejects_sibling_with_same_prefix(tmp_path: Path) -> None:
    base = tmp_path / "app"
    base.mkdir()
    sibling = tmp_path / "app-secrets" / "nginx.conf"

    with pytest.raises(UnsafePathError):
        resolve_within(sibling, base)


def test_resolve_within_rejects_symlink_escaping_base(tmp_path: Path) -> None:
    base = tmp_path / "allowed"
    base.mkdir()
    secret = tmp_path / "secret.conf"
    secret.write_text("", encoding="utf-8")
    link = base / "link.conf"

    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("Symlinks are not available on this system")

    with pytest.raises(UnsafePathError):
        resolve_within(link, base)


def test_allowed_base_dir_reads_environment_variable(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(BASE_DIR_VARIABLE, str(tmp_path))

    assert allowed_base_dir() == tmp_path


def test_allowed_base_dir_defaults_to_current_directory(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(BASE_DIR_VARIABLE, raising=False)
    monkeypatch.chdir(tmp_path)

    assert allowed_base_dir() == Path(os.getcwd())
