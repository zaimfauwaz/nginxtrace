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

def format_directive(directive: Directive) -> str:
    """Render one directive as single-line evidence text.

    Children are not included. Arguments are joined by single spaces, so the
    original quoting and whitespace are not reproduced exactly.
    """
    parts = (directive.name, *directive.arguments)
    terminator = " {" if directive.children is not None else ";"
    return " ".join(parts) + terminator
