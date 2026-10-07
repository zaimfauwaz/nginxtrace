from pathlib import Path

from nginxtrace.config.models import Directive
from nginxtrace.config.parser import parse
from nginxtrace.rules.http_listen import http_listen_configuration


def parse_directive(config: str) -> Directive:
    directives = parse(config, Path("nginx.conf"))
    return directives[0]


def test_recognizes_bare_port_80() -> None:
    directive = parse_directive("listen 80;")

    configuration = http_listen_configuration(directive)

    assert configuration is not None
    assert configuration.directive == directive
    assert configuration.port == 80


def test_recognizes_port_80_with_options() -> None:
    directive = parse_directive("listen 80 default_server reuseport;")

    configuration = http_listen_configuration(directive)

    assert configuration is not None
    assert configuration.port == 80


def test_recognizes_wildcard_ipv4_port_80() -> None:
    directive = parse_directive("listen *:80;")

    configuration = http_listen_configuration(directive)

    assert configuration is not None
    assert configuration.port == 80


def test_recognizes_ipv4_port_80() -> None:
    directive = parse_directive("listen 0.0.0.0:80;")

    configuration = http_listen_configuration(directive)

    assert configuration is not None
    assert configuration.port == 80


def test_recognizes_loopback_ipv4_port_80() -> None:
    directive = parse_directive("listen 127.0.0.1:80;")

    configuration = http_listen_configuration(directive)

    assert configuration is not None
    assert configuration.port == 80


def test_recognizes_ipv6_port_80() -> None:
    directive = parse_directive("listen [::]:80;")

    configuration = http_listen_configuration(directive)

    assert configuration is not None
    assert configuration.port == 80


def test_recognizes_ipv6_loopback_port_80() -> None:
    directive = parse_directive("listen [::1]:80;")

    configuration = http_listen_configuration(directive)

    assert configuration is not None
    assert configuration.port == 80


def test_ignores_https_listener() -> None:
    directive = parse_directive("listen 443 ssl;")

    assert http_listen_configuration(directive) is None


def test_ignores_non_http_tcp_port() -> None:
    directive = parse_directive("listen 8080;")

    assert http_listen_configuration(directive) is None


def test_ignores_unix_socket_listener() -> None:
    directive = parse_directive("listen unix:/run/nginx/nginx.sock;")

    assert http_listen_configuration(directive) is None


def test_ignores_non_listen_directive() -> None:
    directive = parse_directive("server_name example.com;")

    assert http_listen_configuration(directive) is None


def test_ignores_listen_without_arguments() -> None:
    directive = parse_directive("listen;")

    assert http_listen_configuration(directive) is None