import sys
from pathlib import Path

from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.parser import ParseError
from nginxtrace.config.service import parse_file
from nginxtrace.findings.scanner import scan as scan_directives
from nginxtrace.findings.severity import Severity, meets_threshold
from nginxtrace.output import json as json_output
from nginxtrace.output import text as text_output
from nginxtrace.policy.apply import apply_policy
from nginxtrace.policy.loader import PolicyLoadError, load_policy
from nginxtrace.policy.models import Policy
from nginxtrace.rules.registry import default_rules

def run(
        file: Path,
        min_severity: Severity | None = None,
        output_format: str = "text",
        policy_file: Path | None = None,
) -> int:
    try:
        policy = load_policy(policy_file) if policy_file is not None else Policy()
        directives = parse_file(file)
    except (ConfigLoadError, ParseError, PolicyLoadError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    threshold = min_severity or policy.min_severity or Severity.INFO

    findings, suppressed = apply_policy(
        scan_directives(directives, default_rules()),
        policy,
    )
    findings = tuple(
        finding
        for finding in findings
        if meets_threshold(finding.severity, threshold)
    )

    if output_format == "json":
        print(json_output.format_findings(findings, suppressed))
    else:
        print(text_output.format_findings(findings, suppressed))

    if findings:
        return 1

    return 0
