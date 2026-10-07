from pathlib import Path

import pytest

from nginxtrace.config.models import Directive
from nginxtrace.rules.security_headers import (
    HeaderDefinition,
    PermissionsPolicy,
    ReferrerPolicyClass,
    direct_blocks,
    direct_headers,
    disables_permissions_policy_feature,
    effective_headers,
    extract_header,
    has_header,
    hsts_max_age,
    is_https_server,
    permissions_policy,
    referrer_policy_class,
    x_frame_options_value,
)


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

def make_header(
        name: str,
        value: str,
) -> HeaderDefinition:
    directive = make_directive(
        "add_header",
        (name, value),
    )

    return HeaderDefinition(
        name=name.lower(),
        value=value,
        always=False,
        directive=directive,
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

@pytest.mark.parametrize(
    ("value", "expected"),
    (
            ("max-age=31536000", 31536000),
            ('max-age="31536000"', 31536000),
            ("includeSubDomains; max-age=1", 1),
            ("MAX-AGE=31536000", 31536000),
            ("max-age = 31536000", 31536000),
            ("max-age=0", 0),
            (
                    "max-age=31536000; includeSubDomains; preload",
                    31536000,
            ),
    ),
)
def test_hsts_max_age_extracts_valid_max_age(
        value: str,
        expected: int,
) -> None:
    header = make_header("Strict-Transport-Security", value)

    assert hsts_max_age(header) == expected


@pytest.mark.parametrize(
    "value",
    (
            "",
            "includeSubDomains",
            "preload",
            "max-age=",
            'max-age=""',
            "max-age=abc",
            "max-age=-1",
            "max-age=31.5",
            "x-max-age=31536000",
            "not-max-age=31536000",
            "max-age=31536000seconds",
    ),
)
def test_hsts_max_age_returns_none_for_invalid_or_missing_values(
        value: str,
) -> None:
    header = make_header("Strict-Transport-Security", value)

    assert hsts_max_age(header) is None


def test_hsts_max_age_returns_none_for_non_hsts_header() -> None:
    header = make_header("X-Frame-Options", "max-age=31536000")

    assert hsts_max_age(header) is None

@pytest.mark.parametrize(
    ("value", "expected"),
    (
            ("DENY", "DENY"),
            ("deny", "DENY"),
            ("  DenY  ", "DENY"),
            ("SAMEORIGIN", "SAMEORIGIN"),
            ("sameorigin", "SAMEORIGIN"),
            ("  SameOrigin  ", "SAMEORIGIN"),
    ),
)
def test_x_frame_options_value_normalizes_valid_values(
        value: str,
        expected: str,
) -> None:
    header = make_header("X-Frame-Options", value)

    assert x_frame_options_value(header) == expected


@pytest.mark.parametrize(
    "value",
    (
            "",
            " ",
            "ALLOW-FROM",
            "ALLOW-FROM https://trusted.example",
            "SAME-ORIGIN",
            "ALLOWALL",
            "*",
            "DENY extra",
            "DENY;",
            "SAMEORIGIN;",
    ),
)
def test_x_frame_options_value_rejects_invalid_or_obsolete_values(
        value: str,
) -> None:
    header = make_header("X-Frame-Options", value)

    assert x_frame_options_value(header) is None


def test_x_frame_options_value_rejects_non_xfo_header() -> None:
    header = make_header("X-Content-Type-Options", "DENY")

    assert x_frame_options_value(header) is None

@pytest.mark.parametrize(
    "value",
    (
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "  Strict-Origin-When-Cross-Origin  ",
    ),
)
def test_referrer_policy_class_recognizes_recommended_policies(
        value: str,
) -> None:
    header = make_header("Referrer-Policy", value)

    assert referrer_policy_class(header) is ReferrerPolicyClass.RECOMMENDED


@pytest.mark.parametrize(
    "value",
    (
            "origin",
            "origin-when-cross-origin",
            "  ORIGIN  ",
    ),
)
def test_referrer_policy_class_recognizes_permissive_policies(
        value: str,
) -> None:
    header = make_header("Referrer-Policy", value)

    assert referrer_policy_class(header) is ReferrerPolicyClass.PERMISSIVE


@pytest.mark.parametrize(
    "value",
    (
            "",
            " ",
            "unsafe-url",
            "no-referrer-when-downgrade",
            "strict-origin extra",
            "origin; unsafe-url",
            "unknown-policy",
    ),
)
def test_referrer_policy_class_rejects_unsafe_or_invalid_values(
        value: str,
) -> None:
    header = make_header("Referrer-Policy", value)

    assert referrer_policy_class(header) is ReferrerPolicyClass.INVALID


def test_referrer_policy_class_rejects_non_referrer_policy_header() -> None:
    header = make_header(
        "X-Content-Type-Options",
        "strict-origin-when-cross-origin",
    )

    assert referrer_policy_class(header) is None

def test_permissions_policy_returns_none_for_non_permissions_policy_header() -> None:
    header = make_header("X-Frame-Options", "camera=()")

    assert permissions_policy(header) is None


def test_permissions_policy_parses_baseline_disabled_features() -> None:
    header = make_header(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )

    policy = permissions_policy(header)

    assert policy == PermissionsPolicy(
        disabled_features=frozenset(
            {
                "camera",
                "microphone",
                "geolocation",
            }
        ),
        configured_features=frozenset(
            {
                "camera",
                "microphone",
                "geolocation",
            }
        ),
        is_valid=True,
    )


def test_permissions_policy_normalizes_feature_name_case() -> None:
    header = make_header(
        "Permissions-Policy",
        "Camera=(), MICROPHONE=()",
    )

    policy = permissions_policy(header)

    assert policy is not None
    assert policy.disabled_features == frozenset({"camera", "microphone"})
    assert policy.configured_features == frozenset({"camera", "microphone"})
    assert policy.is_valid is True


def test_permissions_policy_accepts_wildcard_allowlist() -> None:
    header = make_header(
        "Permissions-Policy",
        "camera=*",
    )

    policy = permissions_policy(header)

    assert policy == PermissionsPolicy(
        disabled_features=frozenset(),
        configured_features=frozenset({"camera"}),
        is_valid=True,
    )


def test_permissions_policy_tracks_disabled_and_wildcard_features() -> None:
    header = make_header(
        "Permissions-Policy",
        "camera=(), microphone=*, geolocation=()",
    )

    policy = permissions_policy(header)

    assert policy == PermissionsPolicy(
        disabled_features=frozenset({"camera", "geolocation"}),
        configured_features=frozenset(
            {
                "camera",
                "microphone",
                "geolocation",
            }
        ),
        is_valid=True,
    )


@pytest.mark.parametrize(
    "value",
    (
            "",
            " ",
            "camera",
            "camera=",
            "camera=(*",
            "camera=() extra",
            "camera=(self)",
            'camera=("https://trusted.example")',
            "camera=(), camera=*",
            "camera=(), CAMERA=()",
            ", camera=()",
            "camera=(),",
    ),
)
def test_permissions_policy_rejects_unsupported_or_invalid_values(
        value: str,
) -> None:
    header = make_header("Permissions-Policy", value)

    policy = permissions_policy(header)

    assert policy == PermissionsPolicy(
        disabled_features=frozenset(),
        configured_features=frozenset(),
        is_valid=False,
    )


def test_disables_permissions_policy_feature_returns_true_for_disabled_feature() -> None:
    header = make_header(
        "Permissions-Policy",
        "camera=(), microphone=()",
    )

    assert disables_permissions_policy_feature(header, "camera") is True
    assert disables_permissions_policy_feature(header, "MICROPHONE") is True


def test_disables_permissions_policy_feature_returns_false_for_wildcard_feature() -> None:
    header = make_header(
        "Permissions-Policy",
        "camera=*",
    )

    assert disables_permissions_policy_feature(header, "camera") is False


def test_disables_permissions_policy_feature_returns_false_for_missing_feature() -> None:
    header = make_header(
        "Permissions-Policy",
        "camera=()",
    )

    assert disables_permissions_policy_feature(header, "geolocation") is False


def test_disables_permissions_policy_feature_returns_false_for_invalid_policy() -> None:
    header = make_header(
        "Permissions-Policy",
        "camera=(self)",
    )

    assert disables_permissions_policy_feature(header, "camera") is False


def test_disables_permissions_policy_feature_returns_false_for_non_policy_header() -> None:
    header = make_header("X-Frame-Options", "DENY")

    assert disables_permissions_policy_feature(header, "camera") is False