import sys
from pathlib import Path

from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.parser import ParseError
from nginxtrace.config.service import parse_file

def run(file: Path) -> int:
    try:
        parse_file(file)
    except (ConfigLoadError, ParseError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    print(f"Syntax OK: {file.as_posix()}")
    return 0
