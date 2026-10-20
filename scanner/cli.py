import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional
from scanner.orchestrator import scan_project


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanner", description="Context Security Scanner CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a project for security issues")
    scan_parser.add_argument("path", help="Path to the project directory to scan")

    return parser


def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.command == "scan":
        target_path = Path(parsed_args.path)
        findings = scan_project(target_path)
        findings_json = json.dumps([f.to_dict() for f in findings], indent=2)
        print(findings_json)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
