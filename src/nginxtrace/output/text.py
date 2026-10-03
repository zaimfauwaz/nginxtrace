from nginxtrace.findings.models import Finding
from nginxtrace.findings.severity import Severity
from nginxtrace.policy.models import SuppressedFinding

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

def format_suppressed(suppressed: tuple[SuppressedFinding, ...]) -> str:
    lines = ["Suppressed:"]

    for item in suppressed:
        finding = item.finding
        lines.append(
            f"{finding.rule_id} {finding.file.as_posix()}:{finding.line} "
            f"({item.suppression.reason})"
        )

    return "\n".join(lines)

def format_findings(
        findings: tuple[Finding, ...],
        suppressed: tuple[SuppressedFinding, ...] = (),
) -> str:
    if not findings and not suppressed:
        return "No findings."

    blocks = [format_finding(finding) for finding in findings]

    if not findings:
        blocks.append("No findings.")

    if suppressed:
        blocks.append(format_suppressed(suppressed))

    summary = format_summary(findings) if findings else "0 findings"

    if suppressed:
        summary += f", {len(suppressed)} suppressed"

    blocks.append(summary)
    return "\n\n".join(blocks)
