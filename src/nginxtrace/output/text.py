from nginxtrace.findings.models import Finding

def format_finding(finding: Finding) -> str:
    return "\n".join((
        f"{finding.severity.value.upper():<8} {finding.rule_id}",
        finding.message,
        f"File: {finding.file.as_posix()}:{finding.line}"
    ))

def format_findings(findings: tuple[Finding]) -> str:
    if not findings:
        return "No findings."

    return "\n\n".join(format_finding(finding) for finding in findings)