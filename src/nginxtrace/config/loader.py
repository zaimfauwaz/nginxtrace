from pathlib import Path

class ConfigLoadError(ValueError):
    """Raised when loading NGINX config file fails"""

def load_file(file:Path) -> str:
    if not file.exists():
        raise ConfigLoadError(f"Configuration file does not exist: {file}")
    if not file.is_file():
        raise ConfigLoadError(f"Configuration file is not a file: {file}")

    try:
        return file.read_text(encoding="utf-8")
    except OSError as err:
        raise ConfigLoadError(
            f"Could not read configuration file {file}: {err}"
        ) from err