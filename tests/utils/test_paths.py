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
    with pytest.raises(UnsafePathError):
        resolve_within(Path("../outside.conf"), tmp_path)


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

def test_resolve_within_rejects_absolute_external_path(tmp_path: Path) -> None:
    external_path = tmp_path.parent / "outside.conf"

    with pytest.raises(UnsafePathError):
        resolve_within(external_path, tmp_path)


def test_resolve_within_rejects_symlink_escaping_base(tmp_path: Path) -> None:
    external_path = tmp_path.parent / "outside.conf"
    external_path.write_text("secret", encoding="utf-8")

    symlink = tmp_path / "escape.conf"

    try:
        symlink.symlink_to(external_path)
    except OSError as err:
        if os.name == "nt" and getattr(err, "winerror", None) == 1314:
            pytest.skip("Creating symlinks requires Windows Developer Mode or elevation")
        raise

    with pytest.raises(
            UnsafePathError,
            match=r"Path is outside the allowed directory",
    ):
        resolve_within(symlink, tmp_path)


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


