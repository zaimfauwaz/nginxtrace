import pytest

from nginxtrace.config.tokenizer import tokenize


def test_tokenize_simple_directive() -> None:
    tokens = tokenize("listen 80;")

    assert [token.value for token in tokens] == [
        "listen",
        "80",
        ";",
    ]
    assert [token.line for token in tokens] == [
        1,
        1,
        1,
    ]


def test_tokenize_block_directive() -> None:
    tokens = tokenize("server { listen 80; }")

    assert [token.value for token in tokens] == [
        "server",
        "{",
        "listen",
        "80",
        ";",
        "}",
    ]


def test_tokenize_ignores_comments() -> None:
    tokens = tokenize("listen 80; # public HTTP listener")

    assert [token.value for token in tokens] == [
        "listen",
        "80",
        ";",
    ]


def test_tokenize_tracks_line_numbers() -> None:
    tokens = tokenize(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.test;\n"
        "}\n"
    )

    assert [(token.value, token.line) for token in tokens] == [
        ("server", 1),
        ("{", 1),
        ("listen", 2),
        ("80", 2),
        (";", 2),
        ("server_name", 3),
        ("example.test", 3),
        (";", 3),
        ("}", 4),
    ]


def test_tokenize_double_quoted_value() -> None:
    tokens = tokenize('add_header X-Test "hello world";')

    assert [token.value for token in tokens] == [
        "add_header",
        "X-Test",
        "hello world",
        ";",
    ]


def test_tokenize_single_quoted_value() -> None:
    tokens = tokenize("log_format main '$remote_addr - $request';")

    assert [token.value for token in tokens] == [
        "log_format",
        "main",
        "$remote_addr - $request",
        ";",
    ]


def test_tokenize_rejects_unterminated_quote() -> None:
    with pytest.raises(
            ValueError,
            match="Unterminated quoted string starting on line 1",
    ):
        tokenize('add_header X-Test "missing quote;')