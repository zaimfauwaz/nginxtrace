from pathlib import Path

from nginxtrace.config.models import Directive
from nginxtrace.rules.security_headers import HeaderDefinition, direct_blocks, direct_headers, effective_headers, extract_header, has_header, is_https_server


def make_directive(
        name: str,
        arguments: tuple[str, ...] = (),
        children: tuple[Directive, ...] | None = None,
) -> Directive:
    return Directive(
        name=name,
        arguments=arguments,
        file=Path("nginx.conf"),
        line=1,
        children=children,
    )


def test_extract_header_returns_normalized_header_definition() -> None:
    directive = make_directive(
        "add_header",
        ("X-Content-Type-Options", "nosniff"),
    )

    header = extract_header(directive)

    assert header is not None
    assert header.name == "x-content-type-options"
    assert header.value == "nosniff"
    assert header.always is False
    assert header.directive is directive


def test_extract_header_detects_always_argument() -> None:
    directive = make_directive(
        "add_header",
        ("Strict-Transport-Security", "max-age=31536000", "always"),
    )

    header = extract_header(directive)

    assert header is not None
    assert header.name == "strict-transport-security"
    assert header.value == "max-age=31536000"
    assert header.always is True


def test_extract_header_preserves_multi_argument_value() -> None:
    directive = make_directive(
        "add_header",
        (
            "Content-Security-Policy",
            "default-src",
            "'self';",
            "frame-ancestors",
            "'none';",
        ),
    )

    header = extract_header(directive)

    assert header is not None
    assert header.value == "default-src 'self'; frame-ancestors 'none';"


def test_extract_header_ignores_non_header_directive() -> None:
    directive = make_directive("listen", ("80",))

    assert extract_header(directive) is None


def test_extract_header_ignores_incomplete_header_directive() -> None:
    directive = make_directive("add_header", ("X-Frame-Options",))

    assert extract_header(directive) is None


def test_extract_header_ignores_header_with_only_always_argument() -> None:
    directive = make_directive(
        "add_header",
        ("X-Frame-Options", "always"),
    )

    assert extract_header(directive) is None


def test_direct_headers_returns_only_direct_child_headers() -> None:
    nested_header = make_directive(
        "add_header",
        ("X-Frame-Options", "DENY"),
    )
    location = make_directive(
        "location",
        ("/",),
        (nested_header,),
    )
    server = make_directive(
        "server",
        (),
        (
            make_directive(
                "add_header",
                ("X-Content-Type-Options", "nosniff"),
            ),
            make_directive("listen", ("80",)),
            location,
        ),
    )

    headers = direct_headers(server)

    assert [(header.name, header.value) for header in headers] == [
        ("x-content-type-options", "nosniff"),
    ]

def test_effective_headers_inherit_parent_headers_when_child_has_none() -> None:
    parent = make_directive(
        "server",
        (),
        (
            make_directive(
                "add_header",
                ("X-Content-Type-Options", "nosniff"),
            ),
        ),
    )
    child = make_directive(
        "location",
        ("/",),
        (
            make_directive("proxy_pass", ("http://backend",)),
        ),
    )

    headers = effective_headers(parent, child)

    assert [(header.name, header.value) for header in headers] == [
        ("x-content-type-options", "nosniff"),
    ]


def test_effective_headers_use_child_headers_when_child_defines_add_header() -> None:
    parent = make_directive(
        "server",
        (),
        (
            make_directive(
                "add_header",
                ("Strict-Transport-Security", "max-age=31536000", "always"),
            ),
        ),
    )
    child = make_directive(
        "location",
        ("/assets/",),
        (
            make_directive(
                "add_header",
                ("Cache-Control", "public"),
            ),
        ),
    )

    headers = effective_headers(parent, child)

    assert [(header.name, header.value) for header in headers] == [
        ("cache-control", "public"),
    ]


def test_effective_headers_returns_child_headers_when_parent_has_none() -> None:
    parent = make_directive(
        "server",
        (),
        (
            make_directive("listen", ("80",)),
        ),
    )
    child = make_directive(
        "location",
        ("/",),
        (
            make_directive(
                "add_header",
                ("X-Frame-Options", "DENY"),
            ),
        ),
    )

    headers = effective_headers(parent, child)

    assert [(header.name, header.value) for header in headers] == [
        ("x-frame-options", "DENY"),
    ]


def test_effective_headers_returns_empty_tuple_when_no_headers_are_defined() -> None:
    parent = make_directive(
        "server",
        (),
        (
            make_directive("listen", ("80",)),
        ),
    )
    child = make_directive(
        "location",
        ("/",),
        (
            make_directive("proxy_pass", ("http://backend",)),
        ),
    )

    assert effective_headers(parent, child) == ()

def test_is_https_server_detects_ssl_listen_directive() -> None:
    server = make_directive(
        "server",
        (),
        (
            make_directive("listen", ("443", "ssl")),
        ),
    )

    assert is_https_server(server) is True


def test_is_https_server_detects_ssl_with_additional_listen_arguments() -> None:
    server = make_directive(
        "server",
        (),
        (
            make_directive("listen", ("[::]:8443", "ssl", "http2")),
        ),
    )

    assert is_https_server(server) is True


def test_is_https_server_rejects_http_listen_directive() -> None:
    server = make_directive(
        "server",
        (),
        (
            make_directive("listen", ("80",)),
        ),
    )

    assert is_https_server(server) is False


def test_is_https_server_rejects_port_443_without_ssl_argument() -> None:
    server = make_directive(
        "server",
        (),
        (
            make_directive("listen", ("443",)),
        ),
    )

    assert is_https_server(server) is False


def test_is_https_server_rejects_non_server_block() -> None:
    location = make_directive(
        "location",
        ("/",),
        (
            make_directive("listen", ("443", "ssl")),
        ),
    )

    assert is_https_server(location) is False

def test_has_header_matches_name_case_insensitively() -> None:
    headers = (
        HeaderDefinition(
            name="x-content-type-options",
            value="nosniff",
            always=False,
            directive=make_directive(
                "add_header",
                ("X-Content-Type-Options", "nosniff"),
            ),
        ),
    )

    assert has_header(headers, "X-Content-Type-Options") is True


def test_has_header_matches_expected_value_case_insensitively() -> None:
    headers = (
        HeaderDefinition(
            name="x-content-type-options",
            value="NoSnIfF",
            always=False,
            directive=make_directive(
                "add_header",
                ("X-Content-Type-Options", "NoSnIfF"),
            ),
        ),
    )

    assert has_header(
        headers,
        "x-content-type-options",
        "nosniff",
    ) is True


def test_has_header_rejects_wrong_value() -> None:
    headers = (
        HeaderDefinition(
            name="x-content-type-options",
            value="off",
            always=False,
            directive=make_directive(
                "add_header",
                ("X-Content-Type-Options", "off"),
            ),
        ),
    )

    assert has_header(
        headers,
        "X-Content-Type-Options",
        "nosniff",
    ) is False

def test_direct_blocks_returns_only_direct_child_blocks() -> None:
    nested_if = make_directive(
        "if",
        ("$request_method",),
        (
            make_directive(
                "add_header",
                ("X-Test", "nested"),
            ),
        ),
    )
    location = make_directive(
        "location",
        ("/",),
        (nested_if,),
    )
    server = make_directive(
        "server",
        (),
        (
            location,
            make_directive("listen", ("443", "ssl")),
        ),
    )

    blocks = tuple(direct_blocks(server))

    assert blocks == (location,)


def test_direct_blocks_returns_empty_tuple_when_block_has_no_children() -> None:
    directive = make_directive("location", ("/",))

    assert tuple(direct_blocks(directive)) == ()