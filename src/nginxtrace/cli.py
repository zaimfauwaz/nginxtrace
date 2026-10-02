import argparse
from pathlib import Path

from nginxtrace.commands.scan import run as run_scan
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

    return parser

def main() -> None:
    parser = build_parser()
    arguments = parser.parse_args()

    if arguments.command == "scan":
        raise SystemExit(run_scan(arguments.config))

if __name__ == "__main__":
    main()