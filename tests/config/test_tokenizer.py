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

def test_tokenize_keeps_hash_inside_double_quoted_value() -> None:
    tokens = tokenize('add_header X-Note "value # not a comment";')

    assert [token.value for token in tokens] == [
        "add_header",
        "X-Note",
        "value # not a comment",
        ";",
    ]


def test_tokenize_keeps_hash_inside_single_quoted_value() -> None:
    tokens = tokenize("log_format main '$request # preserved';")

    assert [token.value for token in tokens] == [
        "log_format",
        "main",
        "$request # preserved",
        ";",
    ]


def test_tokenize_unescapes_matching_quote_in_double_quoted_value() -> None:
    tokens = tokenize(r'add_header X-Message "say \"hello\"";')

    assert [token.value for token in tokens] == [
        "add_header",
        "X-Message",
        'say "hello"',
        ";",
    ]


def test_tokenize_unescapes_matching_quote_in_single_quoted_value() -> None:
    tokens = tokenize(r"log_format main 'it\'s valid';")

    assert [token.value for token in tokens] == [
        "log_format",
        "main",
        "it's valid",
        ";",
    ]


def test_tokenize_unescapes_backslash_in_quoted_value() -> None:
    tokens = tokenize(r'add_header X-Path "C:\\logs\\nginx";')

    assert [token.value for token in tokens] == [
        "add_header",
        "X-Path",
        r"C:\logs\nginx",
        ";",
    ]


def test_tokenize_accepts_empty_quoted_value() -> None:
    tokens = tokenize('set $value "";')

    assert [token.value for token in tokens] == [
        "set",
        "$value",
        "",
        ";",
    ]

def test_tokenize_preserves_newline_inside_quoted_value() -> None:
    tokens = tokenize(
        'add_header X-Message "first line\n'
        'second line";\n'
        'listen 80;\n'
    )

    assert [(token.value, token.line) for token in tokens] == [
        ("add_header", 1),
        ("X-Message", 1),
        ("first line\nsecond line", 1),
        (";", 2),
        ("listen", 3),
        ("80", 3),
        (";", 3),
    ]


def test_tokenize_tracks_line_after_crlf_input() -> None:
    tokens = tokenize("server {\r\nlisten 80;\r\n}\r\n")

    assert [(token.value, token.line) for token in tokens] == [
        ("server", 1),
        ("{", 1),
        ("listen", 2),
        ("80", 2),
        (";", 2),
        ("}", 3),
    ]


def test_tokenize_separates_structural_characters_without_whitespace() -> None:
    tokens = tokenize("server{listen 80;}")

    assert [token.value for token in tokens] == [
        "server",
        "{",
        "listen",
        "80",
        ";",
        "}",
    ]


def test_tokenize_ignores_comment_at_end_of_input() -> None:
    tokens = tokenize("listen 80; # no final newline")

    assert [token.value for token in tokens] == [
        "listen",
        "80",
        ";",
    ]


def test_tokenize_reports_opening_line_for_multiline_unterminated_quote() -> None:
    with pytest.raises(
            ValueError,
            match="Unterminated quoted string starting on line 2",
    ):
        tokenize(
            "events {}\n"
            'http { add_header X-Message "starts here\n'
            "and never closes;\n"
            "}\n"
        )