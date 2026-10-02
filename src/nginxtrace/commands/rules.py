import sys

from nginxtrace.rules.registry import default_rules, find_rule

def run_list() -> int:
    for rule in default_rules():
        print(
            f"{rule.rule_id:<20} "
            f"{rule.default_severity.value:<8} "
            f"{rule.default_confidence.value:<8} "
            f"{rule.title}"
        )

    return 0

def run_show(rule_id: str) -> int:
    rule = find_rule(rule_id)

    if rule is None:
        print(f"Error: Unknown rule ID: {rule_id}", file=sys.stderr)
        return 2

    print("\n".join((
        f"Rule: {rule.rule_id}",
        f"Title: {rule.title}",
        f"Severity: {rule.default_severity.value}",
        f"Confidence: {rule.default_confidence.value}",
        "",
        rule.description,
        "",
        "Remediation:",
        rule.remediation,
    )))
    return 0
