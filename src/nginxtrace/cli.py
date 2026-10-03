import argparse
from pathlib import Path

from nginxtrace.commands import rules as rules_command
from nginxtrace.commands.check import run as run_check
from nginxtrace.commands.scan import run as run_scan
from nginxtrace.findings.severity import Severity
from nginxtrace.version import VERSION


def add_input_arguments(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config",type=Path,help="Path to the NGINX configuration file.")
    source.add_argument("--dump",type=Path,help="Path to a file with the output of `nginx -T`.")
    parser.add_argument(
        "--no-includes",
        action="store_true",
        help="Do not follow include directives.",
    )

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
    add_input_arguments(scan_parser)
    scan_parser.add_argument(
        "--min-severity",
        type=Severity,
        choices=list(Severity),
        default=None,
        help="Only report findings at or above this severity. Overrides the policy file.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    scan_parser.add_argument("--policy",type=Path,default=None,help="Path to a TOML policy file.")

    check_parser = subparsers.add_parser("check", help="Check NGINX configuration syntax only.")
    add_input_arguments(check_parser)

    rules_parser = subparsers.add_parser("rules", help="List or show detection rules.")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)
    rules_subparsers.add_parser("list", help="List all rules.")
    show_parser = rules_subparsers.add_parser("show", help="Show one rule.")
    show_parser.add_argument("rule_id", help="Rule ID, for example NGX-SECRET-001.")

    return parser

def main(arguments: list[str] | None = None) -> None:
    parser = build_parser()
    parsed_arguments = parser.parse_args(arguments)

    if parsed_arguments.command in ("scan", "check"):
        from_dump = parsed_arguments.dump is not None
        file = parsed_arguments.dump if from_dump else parsed_arguments.config
        resolve_includes = not parsed_arguments.no_includes

    if parsed_arguments.command == "scan":
        raise SystemExit(run_scan(
            file,
            min_severity=parsed_arguments.min_severity,
            output_format=parsed_arguments.format,
            policy_file=parsed_arguments.policy,
            resolve_includes=resolve_includes,
            from_dump=from_dump,
        ))

    if parsed_arguments.command == "check":
        raise SystemExit(run_check(file, resolve_includes, from_dump))

    if parsed_arguments.command == "rules":
        if parsed_arguments.rules_command == "list":
            raise SystemExit(rules_command.run_list())

        raise SystemExit(rules_command.run_show(parsed_arguments.rule_id))

if __name__ == "__main__":
    main()
