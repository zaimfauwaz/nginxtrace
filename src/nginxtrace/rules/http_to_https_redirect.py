from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import format_directive, walk_directives
from nginxtrace.rules.http_listen import http_listen_configuration
from nginxtrace.rules.https_redirect import is_direct_https_return


class HttpToHttpsRedirectRule(Rule):
    rule_id = "NGX-REDIRECT-001"
    title = "HTTP server does not redirect to HTTPS"
    description = (
        "Detects server blocks that explicitly listen on port 80 but do not "
        "contain a recognized direct HTTPS return redirect."
    )
    default_severity = Severity.LOW
    default_confidence = Confidence.MEDIUM
    remediation = (
        "If this server is intended to be public and has an HTTPS endpoint, "
        "redirect HTTP requests to HTTPS, for example: "
        "`return 301 https://$host$request_uri;`."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []

        for server in walk_directives(directives):
            if server.name != "server":
                continue

            children = server.children or ()

            http_listens = tuple(
                configuration
                for child in children
                if (
                    configuration := http_listen_configuration(child)
                ) is not None
            )

            if not http_listens:
                continue

            if any(is_direct_https_return(child) for child in children):
                continue

            for configuration in http_listens:
                findings.append(
                    self.create_finding(
                        configuration.directive,
                        message=(
                            "HTTP listener on port 80 does not have a "
                            "recognized direct HTTPS redirect."
                        ),
                        evidence=(format_directive(configuration.directive),),
                    )
                )

        return tuple(findings)