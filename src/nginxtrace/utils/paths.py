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
    """Resolve file (following symlinks) and require it to be inside base_dir."""
    base = os.path.realpath(base_dir)
    resolved = os.path.realpath(os.path.join(base, file))

    try:
        common = os.path.commonpath([base, resolved])
    except ValueError as err:
        raise UnsafePathError(f"Path is outside the allowed directory {base}: {file}") from err

    if os.path.normcase(common) != os.path.normcase(base):
        raise UnsafePathError(f"Path is outside the allowed directory {base}: {file}")

    return Path(resolved)
