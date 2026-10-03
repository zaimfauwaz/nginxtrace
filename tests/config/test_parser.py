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

def test_parse_rejects_blocks_nested_too_deeply() -> None:
    text = "a {" * 51 + "}" * 51

    with pytest.raises(ParseError, match=r"nested more than 50 levels deep"):
        parse(text, Path("nginx.conf"))


def test_parse_accepts_blocks_nested_at_limit() -> None:
    text = "a {" * 50 + "}" * 50

    directives = parse(text, Path("nginx.conf"))

    assert directives[0].name == "a"

def test_parse_accepts_multiple_directives_on_one_line() -> None:
    directives = parse(
        "listen 80; server_name example.test;",
        Path("nginx.conf"),
    )

    assert [(directive.name, directive.arguments, directive.line) for directive in directives] == [
        ("listen", ("80",), 1),
        ("server_name", ("example.test",), 1),
    ]


def test_parse_accepts_empty_block() -> None:
    directives = parse(
        "events {}",
        Path("nginx.conf"),
    )

    assert len(directives) == 1

    directive = directives[0]

    assert directive.name == "events"
    assert directive.arguments == ()
    assert directive.line == 1
    assert directive.children == ()


def test_parse_preserves_line_for_directive_inside_block() -> None:
    directives = parse(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    http = directives[0]
    server = http.children[0]
    listen = server.children[0]

    assert http.line == 1
    assert server.line == 2
    assert listen.line == 3


def test_parse_preserves_line_for_block_with_arguments() -> None:
    directives = parse(
        "location /api {\n"
        "    proxy_pass http://backend;\n"
        "}\n",
        Path("nginx.conf"),
    )

    location = directives[0]

    assert location.name == "location"
    assert location.arguments == ("/api",)
    assert location.line == 1
    assert location.children is not None
    assert location.children[0].name == "proxy_pass"
    assert location.children[0].line == 2


def test_parse_accepts_quoted_block_argument() -> None:
    directives = parse(
        'location "/files path/" {\n'
        "    try_files $uri =404;\n"
        "}\n",
        Path("nginx.conf"),
    )

    location = directives[0]

    assert location.name == "location"
    assert location.arguments == ("/files path/",)
    assert location.children is not None
    assert location.children[0].name == "try_files"
    assert location.children[0].arguments == ("$uri", "=404")

def test_parse_rejects_empty_statement() -> None:
    with pytest.raises(
            ParseError,
            match="Unexpected token ';' on line 1",
    ):
        parse(
            ";",
            Path("nginx.conf"),
        )


def test_parse_rejects_stray_opening_brace() -> None:
    with pytest.raises(
            ParseError,
            match="Unexpected token '{' on line 1",
    ):
        parse(
            "{",
            Path("nginx.conf"),
        )


def test_parse_rejects_repeated_semicolon() -> None:
    with pytest.raises(
            ParseError,
            match="Unexpected token ';' on line 1",
    ):
        parse(
            "listen 80;;",
            Path("nginx.conf"),
        )


def test_parse_reports_line_for_unexpected_closing_brace() -> None:
    with pytest.raises(
            ParseError,
            match="Unexpected token '}' on line 4",
    ):
        parse(
            "events {\n"
            "    worker_connections 1024;\n"
            "}\n"
            "}\n",
            Path("nginx.conf"),
        )


def test_parse_reports_line_for_missing_semicolon_before_closing_brace() -> None:
    with pytest.raises(
            ParseError,
            match="Unexpected '}' after directive 'listen' on line 3",
    ):
        parse(
            "server {\n"
            "    listen 80\n"
            "}\n",
            Path("nginx.conf"),
        )


def test_parse_reports_line_for_missing_closing_brace_after_multiline_block() -> None:
    with pytest.raises(
            ParseError,
            match="Expected '}' to close directive 'http'",
    ):
        parse(
            "http {\n"
            "    server {\n"
            "        listen 80;\n"
            "    }\n",
            Path("nginx.conf"),
        )