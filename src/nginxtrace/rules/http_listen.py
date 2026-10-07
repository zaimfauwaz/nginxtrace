from dataclasses import dataclass

from nginxtrace.config.models import Directive


_HTTP_PORT = 80


@dataclass(frozen=True)
class HttpListenConfiguration:
    directive: Directive
    port: int


def http_listen_configuration(
        directive: Directive,
) -> HttpListenConfiguration | None:
    if directive.name != "listen" or not directive.arguments:
        return None

    address = directive.arguments[0]

    if address == str(_HTTP_PORT):
        return HttpListenConfiguration(
            directive=directive,
            port=_HTTP_PORT,
        )

    if address.endswith(f":{_HTTP_PORT}"):
        return HttpListenConfiguration(
            directive=directive,
            port=_HTTP_PORT,
        )

    return None