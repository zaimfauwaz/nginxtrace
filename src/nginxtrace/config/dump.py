from pathlib import Path

from nginxtrace.config.loader import ConfigLoadError

HEADER_PREFIX = "# configuration file "
HEADER_SUFFIX = ":"

def split_dump(text: str) -> dict[Path, str]:
    """Split `nginx -T` output into {file path: file content}.

    Each file starts with a line `# configuration file <path>:`. Lines before
    the first header (such as the "syntax is ok" messages) are ignored.
    The first file in the result is the main configuration file.
    """
    sources: dict[Path, str] = {}
    current: Path | None = None
    lines: list[str] = []

    for line in text.splitlines(keepends=True):
        header = line.rstrip("\r\n")

        if header.startswith(HEADER_PREFIX) and header.endswith(HEADER_SUFFIX):
            if current is not None:
                sources[current] = "".join(lines)

            current = Path(header[len(HEADER_PREFIX):-len(HEADER_SUFFIX)])
            lines = []
        elif current is not None:
            lines.append(line)

    if current is not None:
        sources[current] = "".join(lines)

    if not sources:
        raise ConfigLoadError("No '# configuration file <path>:' sections found in dump")

    return sources
