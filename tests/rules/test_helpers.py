from pathlib import Path

from nginxtrace.config.parser import parse
from nginxtrace.rules.helpers import find_directives, walk_directives


def test_walk_directives_visits_nested_directives() -> None:
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

    names = [directive.name for directive in walk_directives(directives)]

    assert names == [
        "http",
        "server",
        "location",
        "proxy_pass",
    ]


def test_walk_directives_visits_sibling_directives() -> None:
    directives = parse(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.test;\n"
        "}\n",
        Path("nginx.conf"),
    )

    names = [directive.name for directive in walk_directives(directives)]

    assert names == [
        "server",
        "listen",
        "server_name",
    ]


def test_find_directives_returns_all_matching_directives() -> None:
    directives = parse(
        "http {\n"
        "    server {\n"
        "        root /var/www/site-a/public;\n"
        "    }\n"
        "\n"
        "    server {\n"
        "        root /var/www/site-b/public;\n"
        "    }\n"
        "}\n",
        Path("nginx.conf"),
    )

    root_directives = find_directives(directives, "root")

    assert len(root_directives) == 2
    assert [directive.arguments for directive in root_directives] == [
        ("/var/www/site-a/public",),
        ("/var/www/site-b/public",),
    ]


def test_find_directives_returns_empty_tuple_when_no_match_exists() -> None:
    directives = parse(
        "server {\n"
        "    listen 80;\n"
        "}\n",
        Path("nginx.conf"),
    )

    assert find_directives(directives, "proxy_pass") == ()