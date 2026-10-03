import sys
from pathlib import Path

from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.parser import ParseError
from nginxtrace.config.service import parse_dump, parse_file

def run(file: Path, resolve_includes: bool = True, from_dump: bool = False) -> int:
    try:
        if from_dump:
            parse_dump(file, resolve_includes)
        else:
            parse_file(file, resolve_includes)
    except (ConfigLoadError, ParseError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    print(f"Syntax OK: {file.as_posix()}")
    return 0
