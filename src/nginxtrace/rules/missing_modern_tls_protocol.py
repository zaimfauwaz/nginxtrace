from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive, walk_directives
from nginxtrace.rules.security_headers import ssl_protocols_configuration

_LEGACY_TLS_PROTOCOLS = frozenset(
    {
        "SSLv2",
        "SSLv3",
        "TLSv1",
        "TLSv1.1",
    }
)

_MODERN_TLS_PROTOCOLS = frozenset(
    {
        "TLSv1.2",
        "TLSv1.3",
    }
)


class MissingModernTlsProtocolRule(Rule):
    rule_id = "NGX-TLS-002"
    title = "TLS protocol policy omits modern TLS"
    description = (
        "Detects explicit ssl_protocols directives that do not enable "
        "TLSv1.2 or TLSv1.3."
    )
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH
    remediation = (
        "Enable TLSv1.2 or TLSv1.3, preferably both, for example: "
        "`ssl_protocols TLSv1.2 TLSv1.3;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in walk_directives(directives):
            configuration = ssl_protocols_configuration(directive)

            if configuration is None:
                continue

            if configuration.protocols & _LEGACY_TLS_PROTOCOLS:
                continue

            if configuration.protocols & _MODERN_TLS_PROTOCOLS:
                continue

            findings.append(
                self.create_finding(
                    directive,
                    message=(
                        "ssl_protocols does not enable TLSv1.2 or TLSv1.3."
                    ),
                    evidence=(format_directive(directive),),
                )
            )

        return tuple(findings)