from pathlib import Path

import pytest

from nginxtrace.utils.paths import BASE_DIR_VARIABLE

REPOSITORY_ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def allow_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Most tests write files into tmp_path, so allow reading from there."""
    monkeypatch.setenv(BASE_DIR_VARIABLE, str(tmp_path))


@pytest.fixture
def allow_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    """For tests that read files from examples/."""
    monkeypatch.setenv(BASE_DIR_VARIABLE, str(REPOSITORY_ROOT))
