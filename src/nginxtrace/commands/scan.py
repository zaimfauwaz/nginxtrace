import sys
from pathlib import Path

from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.parser import ParseError
from nginxtrace.config.service import parse_file
from nginxtrace.findings.scanner import scan as scan_directives
from nginxtrace.findings.severity import Severity, meets_threshold
from nginxtrace.output import json as json_output
from nginxtrace.output import text as text_output
from nginxtrace.rules.registry import default_rules

def run(
        file: Path,
        min_severity: Severity = Severity.INFO,
        output_format: str = "text",
) -> int:
    try:
        directives = parse_file(file)
    except (ConfigLoadError, ParseError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    findings = tuple(
        finding
        for finding in scan_directives(directives, default_rules())
        if meets_threshold(finding.severity, min_severity)
    )

    if output_format == "json":
        print(json_output.format_findings(findings))
    else:
        print(text_output.format_findings(findings))

    if findings:
        return 1

    return 0
