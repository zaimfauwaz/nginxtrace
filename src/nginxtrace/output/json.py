import json

from nginxtrace.findings.models import Finding
from nginxtrace.policy.models import SuppressedFinding

def finding_to_dict(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "title": finding.title,
        "message": finding.message,
        "remediation": finding.remediation,
        "file": finding.file.as_posix(),
        "line": finding.line,
        "evidence": list(finding.evidence),
    }

def format_findings(
        findings: tuple[Finding, ...],
        suppressed: tuple[SuppressedFinding, ...] = (),
) -> str:
    return json.dumps(
        {
            "total": len(findings),
            "findings": [finding_to_dict(finding) for finding in findings],
            "suppressed": [
                {**finding_to_dict(item.finding), "reason": item.suppression.reason}
                for item in suppressed
            ],
        },
        indent=2,
    )
