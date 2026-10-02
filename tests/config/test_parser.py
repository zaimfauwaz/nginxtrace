from pathlib import Path

import pytest

from nginxtrace.config.parser import ParseError, parse


def test_parse_simple_directive() -> None:
    directives = parse("listen 80;", Path("nginx.conf"))

    assert len(directives) == 1

    directive = directives[0]
    assert directive.name == "listen"
    assert directive.arguments == ("80",)
    assert directive.file == Path("nginx.conf")
    assert directive.line == 1
    assert directive.children is None


def test_parse_block_directive() -> None:
    directives = parse(
        "server {\n"
        "    listen 80;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert len(directives) == 1

    server = directives[0]
    assert server.name == "server"
    assert server.arguments == ()
    assert server.line == 1
    assert server.children is not None
    assert len(server.children) == 1

    listen = server.children[0]
    assert listen.name == "listen"
    assert listen.arguments == ("80",)
    assert listen.line == 2
    assert listen.children is None


def test_parse_nested_blocks() -> None:
    directives = parse(
        "http {\n"
        "    server {\n"
        "        location / {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    http = directives[0]
    assert http.name == "http"
    assert http.children is not None

    server = http.children[0]
    assert server.name == "server"
    assert server.children is not None

    location = server.children[0]
    assert location.name == "location"
    assert location.arguments == ("/",)
    assert location.children is not None

    proxy_pass = location.children[0]
    assert proxy_pass.name == "proxy_pass"
    assert proxy_pass.arguments == ("http://backend",)
    assert proxy_pass.children is None


def test_parse_quoted_argument() -> None:
    directives = parse(
        'add_header X-Test "hello world";',
        Path("nginx.conf"),
    )

    directive = directives[0]
    assert directive.name == "add_header"
    assert directive.arguments == (
        "X-Test",
        "hello world",
    )


def test_parse_rejects_missing_semicolon() -> None:
    with pytest.raises(
            ParseError,
            match=r"Expected ';' or '\{' after directive 'listen'",
    ):
        parse("listen 80", Path("nginx.conf"))


def test_parse_rejects_missing_closing_brace() -> None:
    with pytest.raises(
            ParseError,
            match=r"Expected '\}' to close directive 'server'",
    ):
        parse(
            "server {\n"
            "    listen 80;\n",
            Path("nginx.conf"),
        )


def test_parse_rejects_unexpected_closing_brace() -> None:
    with pytest.raises(
            ParseError,
            match=r"Unexpected token '}' on line 1",
    ):
        parse("}", Path("nginx.conf"))