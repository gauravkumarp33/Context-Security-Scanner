import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from scanner.orchestrator import scan_project

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code-security-scanner",
        description="Context-Aware Security Scanner CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a project for security issues")
    scan_parser.add_argument("path", help="Path to the project directory to scan")
    scan_parser.add_argument(
        "--format",
        choices=["json", "human"],
        default="json",
        help="Output format: 'json' (default, schema-compliant) or 'human' (readable terminal report)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 1 if findings at or above this severity are detected",
    )
    scan_parser.add_argument(
        "--exclude",
        nargs="*",
        default=None,
        help="Patterns or paths to exclude from scanning (e.g. --exclude 'tests/*')",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Optional file path to write scan output to",
    )

    return parser


def format_human_report(target_path: Path, findings: List[Dict[str, Any]]) -> str:
    lines = [
        "=" * 64,
        "          Context-Aware Security Scanner Report",
        "=" * 64,
        f"Target Directory : {target_path}",
        f"Total Findings   : {len(findings)}",
        "-" * 64,
    ]

    if not findings:
        lines.append("No security vulnerabilities detected.")
        lines.append("=" * 64)
        return "\n".join(lines)

    for idx, f in enumerate(findings, start=1):
        sev = str(f.get("severity", "unknown")).upper()
        env = f.get("environment", "unknown")
        conf = f.get("confidence", 0.0)
        lines.append(f"[{idx}] {f.get('rule_id', 'UNKNOWN')} [{sev}]")
        lines.append(f"    Location       : {f.get('file')}:{f.get('line')}")
        lines.append(f"    Environment    : {env} (confidence: {conf:.2f})")
        lines.append(f"    Message        : {f.get('message')}")
        lines.append(f"    Recommendation : {f.get('recommendation')}")
        lines.append("-" * 64)

    return "\n".join(lines)


def should_fail(findings: List[Dict[str, Any]], fail_on_severity: Optional[str]) -> bool:
    if not fail_on_severity:
        return False
    threshold = SEVERITY_WEIGHTS.get(fail_on_severity.lower(), 0)
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if SEVERITY_WEIGHTS.get(sev, 0) >= threshold:
            return True
    return False


def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return 2 if e.code != 0 else 0

    if parsed_args.command == "scan":
        target_path = Path(parsed_args.path)

        if not target_path.exists():
            sys.stderr.write(f"Error: Target path does not exist: {target_path}\n")
            return 2

        try:
            findings_objs = scan_project(target_path, exclude=parsed_args.exclude)
            findings_dicts = [f.to_dict() for f in findings_objs]
        except Exception as e:
            sys.stderr.write(f"Scanner Execution Error: {e}\n")
            return 2

        # Format output
        if parsed_args.format == "human":
            output_content = format_human_report(target_path, findings_dicts)
        else:
            output_content = json.dumps(findings_dicts, indent=2)

        # Write to file or stdout
        if parsed_args.output:
            try:
                out_path = Path(parsed_args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(output_content, encoding="utf-8")
            except OSError as err:
                sys.stderr.write(f"Error writing output to {parsed_args.output}: {err}\n")
                return 2
        else:
            print(output_content)

        # Check exit code against failure threshold
        if should_fail(findings_dicts, parsed_args.fail_on):
            return 1

        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
