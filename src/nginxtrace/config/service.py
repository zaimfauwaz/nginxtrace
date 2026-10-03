from pathlib import Path

from nginxtrace.config.dump import split_dump
from nginxtrace.config.includes import expand_includes
from nginxtrace.config.loader import load_file
from nginxtrace.config.models import Directive
from nginxtrace.config.parser import parse

def parse_file(file:Path, resolve_includes: bool = True) -> tuple[Directive, ...]:
    text = load_file(file)
    directives = parse(text, file)

    if not resolve_includes:
        return directives

    return expand_includes(directives, file)

def parse_dump(dump_file: Path, resolve_includes: bool = True) -> tuple[Directive, ...]:
    """Parse `nginx -T` output. Included files are taken from the dump, not from disk."""
    sources = split_dump(load_file(dump_file))
    main_file = next(iter(sources))
    directives = parse(sources[main_file], main_file)

    if not resolve_includes:
        return directives

    return expand_includes(directives, main_file, sources)
