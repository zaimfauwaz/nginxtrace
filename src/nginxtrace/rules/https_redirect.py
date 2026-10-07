from dataclasses import dataclass

from nginxtrace.config.models import Directive


_REDIRECT_STATUS_CODES = frozenset(
    {
        "301",
        "302",
        "303",
        "307",
        "308",
    }
)


@dataclass(frozen=True)
class HttpsReturnRedirect:
    directive: Directive
    status_code: int
    target: str


def https_return_redirect(
        directive: Directive,
) -> HttpsReturnRedirect | None:
    if directive.name != "return":
        return None

    if len(directive.arguments) != 2:
        return None

    status_code, target = directive.arguments

    if status_code not in _REDIRECT_STATUS_CODES:
        return None

    if not target.startswith("https://"):
        return None

    return HttpsReturnRedirect(
        directive=directive,
        status_code=int(status_code),
        target=target,
    )


def is_direct_https_return(directive: Directive) -> bool:
    return https_return_redirect(directive) is not None