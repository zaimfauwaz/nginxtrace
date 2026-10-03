import os
from pathlib import Path

BASE_DIR_VARIABLE = "NGINXTRACE_BASE_DIR"

class UnsafePathError(ValueError):
    """Raised when a path resolves outside the allowed base directory"""

def allowed_base_dir() -> Path:
    """Directory that input files must stay inside.

    Set by the operator through NGINXTRACE_BASE_DIR, not by CLI arguments,
    so a caller of the CLI cannot widen it. Defaults to the current directory.
    """
    return Path(os.environ.get(BASE_DIR_VARIABLE) or os.getcwd())

def resolve_within(file: Path, base_dir: Path) -> Path:
    """Resolve file paths and reject values outside base_dir."""
    base = Path(base_dir).resolve(strict=False)
    resolved = (base / Path(file)).resolve(strict=False)

    try:
        resolved.relative_to(base)
    except ValueError as err:
        raise UnsafePathError(
            f"Path is outside the allowed directory: {file}"
        ) from err

    return resolved