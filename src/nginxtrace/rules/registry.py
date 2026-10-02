from nginxtrace.rules.base import Rule
from nginxtrace.rules.secret_exposure import SecretExposureRule

def default_rules() -> tuple[Rule, ...]:
    return (
        SecretExposureRule(),
    )