import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum

from nginxtrace.config.models import Directive


@dataclass(frozen=True)
class HeaderDefinition:
    name: str
    value: str
    always: bool
    directive: Directive

@dataclass(frozen=True)
class PermissionsPolicy:
    disabled_features: frozenset[str]
    configured_features: frozenset[str]
    is_valid: bool

class ReferrerPolicyClass(StrEnum):
    RECOMMENDED = "recommended"
    PERMISSIVE = "permissive"
    INVALID = "invalid"


_HSTS_MAX_AGE_PATTERN = re.compile(
    r"(?:^|;)\s*max-age\s*=\s*(?:\"(?P<quoted>\d+)\"|(?P<plain>\d+))\s*(?=;|$)",
    re.IGNORECASE,
)

_RECOMMENDED_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)

_PERMISSIVE_REFERRER_POLICIES = frozenset(
    {
        "origin",
        "origin-when-cross-origin",
    }
)

_PERMISSIONS_POLICY_DIRECTIVE_PATTERN = re.compile(
    r"^\s*(?P<feature>[a-z][a-z0-9-]*)\s*=\s*(?P<allowlist>\(\s*\)|\*)\s*$",
    re.IGNORECASE,
)

_PERMISSIONS_POLICY_BASELINE_FEATURES = frozenset(
    {
        "camera",
        "microphone",
        "geolocation",
    }
)


def extract_header(directive: Directive) -> HeaderDefinition | None:
    if directive.name != "add_header":
        return None

    if len(directive.arguments) < 2:
        return None

    name, *arguments = directive.arguments
    always = arguments[-1].lower() == "always"

    if always:
        arguments = arguments[:-1]

    if not arguments:
        return None

    return HeaderDefinition(
        name=name.lower(),
        value=" ".join(arguments),
        always=always,
        directive=directive,
    )

def direct_blocks(block: Directive) -> Iterator[Directive]:
    for child in block.children or ():
        if child.children is not None:
            yield child

def direct_headers(block: Directive) -> tuple[HeaderDefinition, ...]:
    return tuple(
        header
        for child in block.children or ()
        if (header := extract_header(child)) is not None
    )

def effective_headers(
        parent: Directive,
        child: Directive,
) -> tuple[HeaderDefinition, ...]:
    child_headers = direct_headers(child)

    if child_headers:
        return child_headers

    return direct_headers(parent)

def is_https_server(server: Directive) -> bool:
    if server.name != "server":
        return False

    return any(
        child.name == "listen" and "ssl" in child.arguments
        for child in server.children or ()
    )

def has_header(
        headers: tuple[HeaderDefinition, ...],
        name: str,
        value: str | None = None,
) -> bool:
    normalized_name = name.lower()

    return any(
        header.name == normalized_name
        and (value is None or header.value.lower() == value.lower())
        for header in headers
    )

def hsts_max_age(header: HeaderDefinition) -> int | None:
    if header.name != "strict-transport-security":
        return None

    match = _HSTS_MAX_AGE_PATTERN.search(header.value)

    if match is None:
        return None

    value = match.group("quoted") or match.group("plain")

    if value is None:
        return None

    return int(value)

def x_frame_options_value(header: HeaderDefinition) -> str | None:
    if header.name != "x-frame-options":
        return None

    value = header.value.strip().upper()

    if value in {"DENY", "SAMEORIGIN"}:
        return value

    return None

def referrer_policy_class(
        header: HeaderDefinition,
) -> ReferrerPolicyClass | None:
    if header.name != "referrer-policy":
        return None

    value = header.value.strip().lower()

    if value in _RECOMMENDED_REFERRER_POLICIES:
        return ReferrerPolicyClass.RECOMMENDED

    if value in _PERMISSIVE_REFERRER_POLICIES:
        return ReferrerPolicyClass.PERMISSIVE

    return ReferrerPolicyClass.INVALID

def permissions_policy(header: HeaderDefinition) -> PermissionsPolicy | None:
    if header.name != "permissions-policy":
        return None

    directives = header.value.split(",")

    if not directives or not header.value.strip():
        return PermissionsPolicy(
            disabled_features=frozenset(),
            configured_features=frozenset(),
            is_valid=False,
        )

    disabled_features: set[str] = set()
    configured_features: set[str] = set()

    for directive in directives:
        match = _PERMISSIONS_POLICY_DIRECTIVE_PATTERN.fullmatch(directive)

        if match is None:
            return PermissionsPolicy(
                disabled_features=frozenset(),
                configured_features=frozenset(),
                is_valid=False,
            )

        feature = match.group("feature").lower()
        allowlist = match.group("allowlist")

        if feature in configured_features:
            return PermissionsPolicy(
                disabled_features=frozenset(),
                configured_features=frozenset(),
                is_valid=False,
            )

        configured_features.add(feature)

        if allowlist.startswith("("):
            disabled_features.add(feature)

    return PermissionsPolicy(
        disabled_features=frozenset(disabled_features),
        configured_features=frozenset(configured_features),
        is_valid=True,
    )


def disables_permissions_policy_feature(
        header: HeaderDefinition,
        feature: str,
) -> bool:
    policy = permissions_policy(header)

    if policy is None or not policy.is_valid:
        return False

    return feature.lower() in policy.disabled_features