from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive, walk_directives
from nginxtrace.rules.http_listen import http_listen_configuration
from nginxtrace.rules.https_redirect import https_return_redirect


_TEMPORARY_REDIRECT_STATUS_CODES = frozenset(
    {
        302,
        307,
    }
)


class TemporaryHttpsRedirectRule(Rule):
    rule_id = "NGX-REDIRECT-003"
    title = "HTTP redirect is temporary"
    description = (
        "Detects direct HTTPS redirects from port-80 server blocks that "
        "use temporary status code 302 or 307."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.HIGH
    remediation = (
        "If HTTP-to-HTTPS enforcement is intended to be permanent, use "
        "`return 301 https://$host$request_uri;` or "
        "`return 308 https://$host$request_uri;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for server in walk_directives(directives):
            if server.name != "server":
                continue

            children = server.children or ()

            has_http_listener = any(
                http_listen_configuration(child) is not None
                for child in children
            )

            if not has_http_listener:
                continue

            for directive in children:
                redirect = https_return_redirect(directive)

                if redirect is None:
                    continue

                if redirect.status_code not in _TEMPORARY_REDIRECT_STATUS_CODES:
                    continue

                findings.append(
                    self.create_finding(
                        directive,
                        message=(
                            "HTTP-to-HTTPS redirect uses temporary status "
                            f"{redirect.status_code}; use 301 or 308 if "
                            "the redirect is intended to be permanent."
                        ),
                        evidence=(format_directive(directive),),
                    )
                )

        return tuple(findings)