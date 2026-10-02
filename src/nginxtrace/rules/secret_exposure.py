from nginxtrace.config.models import Directive
from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.rules.base import Rule
from nginxtrace.rules.helpers import find_directives

class SecretExposureRule(Rule):
    rule_id = "NGX-SECRET-001"
    title = "Potential sensitive dotfile exposure"

    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        root_directives = find_directives(directives, "root")

        if not root_directives:
            return ()

        if self.has_dotfile_protection(directives):
            return ()

        return tuple(
            Finding(
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                message=("A root directive was found, but no dotfile denial "
                         "location was detected."),
                file=directive.file,
                line=directive.line,
            )
            for directive in root_directives
        )


    def has_dotfile_protection(self,
       directives: tuple[Directive, ...],
   ) -> bool:
        location_directives = find_directives(directives, "location")

        for directive in location_directives:
            if any(argument.startswith("/\\.") for argument in directive.arguments):
                return True

        return False