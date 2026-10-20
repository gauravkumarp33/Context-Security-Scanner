import json
from pathlib import Path
import jsonschema
import pytest

from scanner.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent / "schema" / "finding.schema.json"


@pytest.fixture
def finding_schema():
    with open(SCHEMA_PATH, "r", encoding="utf-8") as sf:
        return json.load(sf)


def test_integration_clean_project(capsys):
    """Clean project scan should return 0 findings, exit code 0, and valid schema."""
    clean_dir = FIXTURES_DIR / "clean_project"
    exit_code = main(["scan", str(clean_dir), "--format", "json"])

    assert exit_code == 0
    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    assert isinstance(findings, list)
    assert len(findings) == 0


def test_integration_vulnerable_project(capsys, finding_schema):
    """Vulnerable project should report finding, pass schema validation, and adhere to fail-on threshold."""
    vuln_dir = FIXTURES_DIR / "vulnerable_project"

    # Scan with no fail-on: exit code 0
    exit_code_no_fail = main(["scan", str(vuln_dir), "--format", "json"])
    assert exit_code_no_fail == 0
    captured = capsys.readouterr()
    findings = json.loads(captured.out)

    assert len(findings) >= 1
    jsonschema.validate(instance=findings, schema=finding_schema)

    # Scan with fail-on high: exit code 1
    exit_code_fail = main(["scan", str(vuln_dir), "--format", "json", "--fail-on", "high"])
    assert exit_code_fail == 1


def test_integration_human_format_output(capsys):
    """Human-readable format should print structured ASCII report."""
    vuln_dir = FIXTURES_DIR / "vulnerable_project"
    exit_code = main(["scan", str(vuln_dir), "--format", "human"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Context-Aware Security Scanner Report" in captured.out
    assert "Total Findings" in captured.out
    assert "firebase-open-access" in captured.out


def test_integration_output_to_file(tmp_path):
    """Output written to a file should match the requested format."""
    vuln_dir = FIXTURES_DIR / "vulnerable_project"
    report_file = tmp_path / "sub" / "report.json"

    exit_code = main(["scan", str(vuln_dir), "--format", "json", "-o", str(report_file)])
    assert exit_code == 0
    assert report_file.exists()

    content = json.loads(report_file.read_text(encoding="utf-8"))
    assert isinstance(content, list)
    assert len(content) >= 1


def test_integration_invalid_path_returns_exit_code_2(capsys):
    """Non-existent path should return exit code 2 and write error to stderr."""
    exit_code = main(["scan", "non/existent/path/for/sure"])
    assert exit_code == 2

    captured = capsys.readouterr()
    assert "Error: Target path does not exist" in captured.err
