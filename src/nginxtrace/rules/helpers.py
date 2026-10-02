from collections.abc import Iterator

from nginxtrace.config.models import Directive

def walk_directives(
        directives: tuple[Directive, ...],
) -> Iterator[Directive]:
    for directive in directives:
        yield directive

        if directive.children is not None:
            yield from walk_directives(directive.children)

def find_directives(
        directives: tuple[Directive, ...],
        name: str
) -> tuple[Directive, ...]:
    return tuple(
        directive
        for directive in walk_directives(directives)
        if directive.name == name
    )