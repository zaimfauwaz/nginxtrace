from abc import ABC, abstractmethod

from nginxtrace.config.models import Directive
from nginxtrace.findings.models import Finding

class Rule(ABC):
    rule_id: str
    title: str

    @abstractmethod
    def evaluate(self, directives: tuple[Directive, ...]) -> tuple[Finding, ...]:
        """Inspect parsed directives and return any findings."""