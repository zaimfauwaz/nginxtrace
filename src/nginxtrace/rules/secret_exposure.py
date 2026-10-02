from nginxtrace.config.models import Directive
from nginxtrace.findings.confidence import Confidence
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives, format_directive

class SecretExposureRule(Rule):
    rule_id = "NGX-SECRET-001"
    title = "Potential sensitive dotfile exposure"
    description = (
        "Detects a root directive without a detected location intended "
        "to protect dot-prefixed files."
    )
    default_severity = Severity.HIGH
    default_confidence = Confidence.MEDIUM
    remediation = (
        "Add and verify an effective location rule that blocks dotfiles.\n"
        "Validate the final loaded configuration with nginx -t and nginx -T."
    )

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        root_directives = find_directives(directives, "root")

        if not root_directives:
            return ()

        if self.has_dotfile_protection(directives):
            return ()

        return tuple(
            self.create_finding(
                directive,
                message=("A root directive was found, but no dotfile denial "
                         "location was detected."),
                evidence=(format_directive(directive),),
            )
            for directive in root_directives
        )


    def has_dotfile_protection(self,
       directives: tuple[Directive, ...],
   ) -> bool:
        location_directives = find_directives(directives, "location")

        for directive in location_directives:
            if not any(argument.startswith("/\\.") for argument in directive.arguments):
                continue

            for child in directive.children or ():
                if child.name == "deny" and child.arguments == ("all",):
                    return True

        return False
