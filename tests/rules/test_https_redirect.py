from pathlib import Path

from nginxtrace.config.models import Directive
from nginxtrace.config.parser import parse
from nginxtrace.rules.https_redirect import (
    HttpsReturnRedirect,
    https_return_redirect,
    is_direct_https_return,
)


def parse_directive(config: str) -> Directive:
    directives = parse(config, Path("nginx.conf"))
    return directives[0]


def test_parses_301_https_return() -> None:
    directive = parse_directive("return 301 https://$host$request_uri;")

    redirect = https_return_redirect(directive)

    assert redirect == HttpsReturnRedirect(
        directive=directive,
        status_code=301,
        target="https://$host$request_uri",
    )


def test_parses_302_https_return() -> None:
    directive = parse_directive("return 302 https://example.com$request_uri;")

    redirect = https_return_redirect(directive)

    assert redirect is not None
    assert redirect.status_code == 302
    assert redirect.target == "https://example.com$request_uri"


def test_parses_303_https_return() -> None:
    directive = parse_directive("return 303 https://example.com/login;")

    redirect = https_return_redirect(directive)

    assert redirect is not None
    assert redirect.status_code == 303


def test_parses_307_https_return() -> None:
    directive = parse_directive("return 307 https://$host$request_uri;")

    redirect = https_return_redirect(directive)

    assert redirect is not None
    assert redirect.status_code == 307


def test_parses_308_https_return() -> None:
    directive = parse_directive("return 308 https://$host$request_uri;")

    redirect = https_return_redirect(directive)

    assert redirect is not None
    assert redirect.status_code == 308


def test_boolean_wrapper_recognizes_https_return() -> None:
    directive = parse_directive("return 301 https://$host$request_uri;")

    assert is_direct_https_return(directive) is True


def test_ignores_non_return_directive() -> None:
    directive = parse_directive("server_name example.com;")

    assert https_return_redirect(directive) is None


def test_ignores_non_redirect_status_code() -> None:
    directive = parse_directive("return 200 https://example.com;")

    assert https_return_redirect(directive) is None


def test_ignores_http_redirect_target() -> None:
    directive = parse_directive("return 301 http://example.com$request_uri;")

    assert https_return_redirect(directive) is None


def test_ignores_scheme_variable_target() -> None:
    directive = parse_directive("return 301 $scheme://$host$request_uri;")

    assert https_return_redirect(directive) is None


def test_ignores_relative_redirect_target() -> None:
    directive = parse_directive("return 301 /login;")

    assert https_return_redirect(directive) is None


def test_ignores_return_without_url() -> None:
    directive = parse_directive("return 301;")

    assert https_return_redirect(directive) is None


def test_ignores_malformed_return_with_extra_argument() -> None:
    directive = parse_directive("return 301 https://example.com extra;")

    assert https_return_redirect(directive) is None