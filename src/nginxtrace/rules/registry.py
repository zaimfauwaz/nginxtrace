from nginxtrace.rules.base import Rule
from nginxtrace.rules.secret_exposure import SecretExposureRule

def default_rules() -> tuple[Rule, ...]:
    return (
        SecretExposureRule(),
    )

def find_rule(rule_id: str) -> Rule | None:
    for rule in default_rules():
        if rule.rule_id == rule_id:
            return rule

    return None
