from nginxtrace.findings.models import Finding

def format_finding(finding: Finding) -> str:
    lines = [
        f"{finding.severity.value.upper():<8} {finding.rule_id}",
        finding.title,
        "",
        f"File: {finding.file.as_posix()}:{finding.line}",
        f"Confidence: {finding.confidence.value}",
        "",
        finding.message,
        "",
        "Remediation:",
        finding.remediation,
    ]

    if finding.evidence:
        lines.extend(("", "Evidence:", *finding.evidence))

    return "\n".join(lines)

def format_findings(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return "No findings."

    return "\n\n".join(format_finding(finding) for finding in findings)
