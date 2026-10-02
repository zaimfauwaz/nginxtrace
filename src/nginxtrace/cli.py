import argparse
from pathlib import Path

from nginxtrace.commands import rules as rules_command
from nginxtrace.commands.check import run as run_check
from nginxtrace.commands.scan import run as run_scan
from nginxtrace.findings.severity import Severity
from nginxtrace.version import VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nginxtrace",
        description="Scan NGINX configuration for common issues.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan an NGINX configuration file.")
    scan_parser.add_argument("--config",type=Path,required=True,help="Path to the NGINX configuration file.")
    scan_parser.add_argument(
        "--min-severity",
        type=Severity,
        choices=list(Severity),
        default=Severity.INFO,
        help="Only report findings at or above this severity.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    check_parser = subparsers.add_parser("check", help="Check NGINX configuration syntax only.")
    check_parser.add_argument("--config",type=Path,required=True,help="Path to the NGINX configuration file.")

    rules_parser = subparsers.add_parser("rules", help="List or show detection rules.")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)
    rules_subparsers.add_parser("list", help="List all rules.")
    show_parser = rules_subparsers.add_parser("show", help="Show one rule.")
    show_parser.add_argument("rule_id", help="Rule ID, for example NGX-SECRET-001.")

    return parser

def main(arguments: list[str] | None = None) -> None:
    parser = build_parser()
    parsed_arguments = parser.parse_args(arguments)

    if parsed_arguments.command == "scan":
        raise SystemExit(run_scan(
            parsed_arguments.config,
            min_severity=parsed_arguments.min_severity,
            output_format=parsed_arguments.format,
        ))

    if parsed_arguments.command == "check":
        raise SystemExit(run_check(parsed_arguments.config))

    if parsed_arguments.command == "rules":
        if parsed_arguments.rules_command == "list":
            raise SystemExit(rules_command.run_list())

        raise SystemExit(rules_command.run_show(parsed_arguments.rule_id))

if __name__ == "__main__":
    main()
