import argparse

from version import VERSION

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
    return parser


def main() -> None:
    parser = build_parser()
    parser.parse_args()


if __name__ == "__main__":
    main()