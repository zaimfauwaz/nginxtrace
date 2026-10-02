from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity

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

def format_summary(findings: tuple[Finding, ...]) -> str:
    counts: list[str] = []

    for severity in reversed(Severity):
        count = sum(1 for finding in findings if finding.severity == severity)

        if count:
            counts.append(f"{count} {severity.value}")

    noun = "finding" if len(findings) == 1 else "findings"
    return f"{len(findings)} {noun} ({', '.join(counts)})"

def format_findings(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return "No findings."

    blocks = [format_finding(finding) for finding in findings]
    blocks.append(format_summary(findings))
    return "\n\n".join(blocks)
