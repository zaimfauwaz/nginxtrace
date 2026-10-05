import re
from collections.abc import Iterator
from dataclasses import dataclass

from nginxtrace.config.models import Directive


@dataclass(frozen=True)
class HeaderDefinition:
    name: str
    value: str
    always: bool
    directive: Directive

_HSTS_MAX_AGE_PATTERN = re.compile(
    r"(?:^|;)\s*max-age\s*=\s*(?:\"(?P<quoted>\d+)\"|(?P<plain>\d+))\s*(?=;|$)",
    re.IGNORECASE,
)


def extract_header(directive: Directive) -> HeaderDefinition | None:
    if directive.name != "add_header":
        return None

    if len(directive.arguments) < 2:
        return None

    name, *arguments = directive.arguments
    always = arguments[-1].lower() == "always"

    if always:
        arguments = arguments[:-1]

    if not arguments:
        return None

    return HeaderDefinition(
        name=name.lower(),
        value=" ".join(arguments),
        always=always,
        directive=directive,
    )

def direct_blocks(block: Directive) -> Iterator[Directive]:
    for child in block.children or ():
        if child.children is not None:
            yield child

def direct_headers(block: Directive) -> tuple[HeaderDefinition, ...]:
    return tuple(
        header
        for child in block.children or ()
        if (header := extract_header(child)) is not None
    )

def effective_headers(
        parent: Directive,
        child: Directive,
) -> tuple[HeaderDefinition, ...]:
    child_headers = direct_headers(child)

    if child_headers:
        return child_headers

    return direct_headers(parent)

def is_https_server(server: Directive) -> bool:
    if server.name != "server":
        return False

    return any(
        child.name == "listen" and "ssl" in child.arguments
        for child in server.children or ()
    )

def has_header(
        headers: tuple[HeaderDefinition, ...],
        name: str,
        value: str | None = None,
) -> bool:
    normalized_name = name.lower()

    return any(
        header.name == normalized_name
        and (value is None or header.value.lower() == value.lower())
        for header in headers
    )

def hsts_max_age(header: HeaderDefinition) -> int | None:
    if header.name != "strict-transport-security":
        return None

    match = _HSTS_MAX_AGE_PATTERN.search(header.value)

    if match is None:
        return None

    value = match.group("quoted") or match.group("plain")

    if value is None:
        return None

    return int(value)