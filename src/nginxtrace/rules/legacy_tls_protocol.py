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


class LegacyTlsProtocolRule(Rule):
    rule_id = "NGX-TLS-001"
    title = "Legacy TLS protocol enabled"
    description = (
        "Detects ssl_protocols directives that explicitly enable SSLv2, "
        "SSLv3, TLSv1, or TLSv1.1."
    )
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH
    remediation = (
        "Remove legacy protocols and allow only modern TLS versions, for "
        "example: `ssl_protocols TLSv1.2 TLSv1.3;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for directive in walk_directives(directives):
            configuration = ssl_protocols_configuration(directive)

            if configuration is None:
                continue

            legacy_protocols = tuple(
                protocol
                for protocol in sorted(_LEGACY_TLS_PROTOCOLS)
                if protocol in configuration.protocols
            )

            if not legacy_protocols:
                continue

            findings.append(
                self.create_finding(
                    directive,
                    message=(
                        "ssl_protocols explicitly enables legacy protocol(s): "
                        f"{', '.join(legacy_protocols)}."
                    ),
                    evidence=(format_directive(directive),),
                )
            )

        return tuple(findings)