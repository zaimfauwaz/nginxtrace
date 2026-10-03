from dataclasses import replace

from nginxtrace.findings.models import Finding
from nginxtrace.policy.models import Policy, SuppressedFinding

def apply_policy(
        findings: tuple[Finding, ...],
        policy: Policy,
) -> tuple[tuple[Finding, ...], tuple[SuppressedFinding, ...]]:
    kept: list[Finding] = []
    suppressed: list[SuppressedFinding] = []

    for finding in findings:
        if finding.rule_id in policy.disabled_rules:
            continue

        override = policy.severity_overrides.get(finding.rule_id)
        if override is not None:
            finding = replace(finding, severity=override)

        suppression = next(
            (suppression for suppression in policy.suppressions if suppression.matches(finding)),
            None,
        )

        if suppression is not None:
            suppressed.append(SuppressedFinding(finding, suppression))
        else:
            kept.append(finding)

    return tuple(kept), tuple(suppressed)
