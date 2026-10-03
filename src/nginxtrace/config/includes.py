from dataclasses import replace
from fnmatch import fnmatchcase
from pathlib import Path

from nginxtrace.config.loader import ConfigLoadError, load_file
from nginxtrace.config.models import Directive
from nginxtrace.config.parser import MAX_NESTING_DEPTH, ParseError, parse
from nginxtrace.utils.paths import UnsafePathError, allowed_base_dir, resolve_within

MAX_INCLUDED_FILES = 1000
MAX_INCLUDE_DEPTH = 32
WILDCARD_CHARACTERS = ("*", "?", "[")

def has_wildcard(value: str) -> bool:
    return any(character in value for character in WILDCARD_CHARACTERS)

def matches_pattern(name: str, pattern: str) -> bool:
    """Match like glob(3): wildcards do not match a leading dot."""
    if name.startswith(".") and not pattern.startswith("."):
        return False
    return fnmatchcase(name, pattern)

class IncludeResolver:
    """Replaces include directives with the directives of the included files.

    With sources=None files are read from disk through load_file(), so every
    file passes the base directory check. With sources (from an nginx -T dump)
    nothing is read from disk at all.
    """

    def __init__(self, sources: dict[Path, str] | None = None) -> None:
        self.sources = sources
        self.included_files = 0

    def expand(
            self,
            directives: tuple[Directive, ...],
            config_dir: Path,
            chain: tuple[Path, ...],
            nesting: int = 0,
    ) -> tuple[Directive, ...]:
        """nesting counts block levels across files, so includes cannot exceed the parser limit."""
        expanded: list[Directive] = []

        for directive in directives:
            if directive.name == "include" and directive.children is None:
                expanded.extend(self.include(directive, config_dir, chain, nesting))
            elif directive.children is not None:
                if nesting + 1 > MAX_NESTING_DEPTH:
                    raise ConfigLoadError(
                        f"Blocks are nested more than {MAX_NESTING_DEPTH} levels deep "
                        f"across included files ({directive.file.as_posix()}:{directive.line})"
                    )
                children = self.expand(directive.children, config_dir, chain, nesting + 1)
                expanded.append(replace(directive, children=children))
            else:
                expanded.append(directive)

        return tuple(expanded)

    def include(
            self,
            directive: Directive,
            config_dir: Path,
            chain: tuple[Path, ...],
            nesting: int,
    ) -> list[Directive]:
        location = f"included from {directive.file.as_posix()}:{directive.line}"

        if len(directive.arguments) != 1:
            raise ConfigLoadError(
                f"include expects exactly one argument ({directive.file.as_posix()}:{directive.line})"
            )

        directives: list[Directive] = []

        for file in self.matching_files(config_dir / directive.arguments[0], location):
            identity = self.identity(file, location)

            if identity in chain:
                names = " -> ".join(path.as_posix() for path in (*chain, identity))
                raise ConfigLoadError(f"Include cycle detected: {names}")

            if len(chain) >= MAX_INCLUDE_DEPTH:
                raise ConfigLoadError(
                    f"Includes are nested more than {MAX_INCLUDE_DEPTH} levels deep ({location})"
                )

            self.included_files += 1
            if self.included_files > MAX_INCLUDED_FILES:
                raise ConfigLoadError(
                    f"More than {MAX_INCLUDED_FILES} included files ({location})"
                )

            try:
                children = parse(self.read(file, location), file)
            except ParseError as err:
                raise ParseError(f"{file.as_posix()}: {err}") from err

            directives.extend(self.expand(children, config_dir, (*chain, identity), nesting))

        return directives

    def matching_files(self, path: Path, location: str) -> list[Path]:
        if has_wildcard(path.parent.as_posix()):
            raise ConfigLoadError(
                f"Wildcards are only supported in the file name of an include ({location})"
            )

        if not has_wildcard(path.name):
            return [path]

        if self.sources is not None:
            return sorted(
                file
                for file in self.sources
                if file.parent == path.parent and matches_pattern(file.name, path.name)
            )

        try:
            directory = resolve_within(path.parent, allowed_base_dir())
        except UnsafePathError as err:
            raise ConfigLoadError(f"{err} ({location})") from err

        if not directory.is_dir():
            return []

        names = sorted(
            entry.name
            for entry in directory.iterdir()
            if matches_pattern(entry.name, path.name)
        )
        return [path.parent / name for name in names]

    def identity(self, file: Path, location: str) -> Path:
        """Path used to detect include cycles."""
        if self.sources is not None:
            return file

        try:
            return resolve_within(file, allowed_base_dir())
        except UnsafePathError as err:
            raise ConfigLoadError(f"{err} ({location})") from err

    def read(self, file: Path, location: str) -> str:
        if self.sources is not None:
            if file not in self.sources:
                raise ConfigLoadError(
                    f"Included file is not in the dump: {file.as_posix()} ({location})"
                )
            return self.sources[file]

        try:
            return load_file(file)
        except ConfigLoadError as err:
            raise ConfigLoadError(f"{err} ({location})") from err

def expand_includes(
        directives: tuple[Directive, ...],
        main_file: Path,
        sources: dict[Path, str] | None = None,
) -> tuple[Directive, ...]:
    """Expand includes; relative paths are relative to main_file's directory."""
    resolver = IncludeResolver(sources)
    identity = resolver.identity(main_file, main_file.as_posix())
    return resolver.expand(directives, main_file.parent, (identity,))
