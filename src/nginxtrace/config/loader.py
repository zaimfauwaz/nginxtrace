from pathlib import Path

from nginxtrace.utils.paths import UnsafePathError, allowed_base_dir, resolve_within

class ConfigLoadError(ValueError):
    """Raised when loading NGINX config file fails"""

def load_file(file:Path) -> str:
    try:
        safe_file = resolve_within(file, allowed_base_dir())
    except UnsafePathError as err:
        raise ConfigLoadError(str(err)) from err

    if not safe_file.exists():
        raise ConfigLoadError(f"Configuration file does not exist: {file}")
    if not safe_file.is_file():
        raise ConfigLoadError(f"Configuration file is not a file: {file}")

    try:
        return safe_file.read_text(encoding="utf-8")
    except OSError as err:
        raise ConfigLoadError(
            f"Could not read configuration file {file}: {err}"
        ) from err
