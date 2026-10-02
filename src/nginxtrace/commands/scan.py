from pathlib import Path

from nginxtrace.config.loader import ConfigLoadError
from nginxtrace.config.parser import ParseError
from nginxtrace.config.service import parse_file
from nginxtrace.findings.scanner import scan as scan_directives
from nginxtrace.output.text import format_findings
from nginxtrace.rules.registry import default_rules

def run(file: Path) -> int:
    try:
        directives = parse_file(file)
    except (ConfigLoadError, ParseError) as e:
        print(f"Error: {e}")
        return 2

    findings = scan_directives(directives, default_rules())

    print(format_findings(findings))

    if findings:
        return 1

    return 0