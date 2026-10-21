import json
import subprocess
import sys
from pathlib import Path
import jsonschema
import pytest

from scanner.cli import main


def test_cli_runs_end_to_end_on_temp_project(tmp_path):
    """Verify that python -m scanner scan <path> runs end to end and outputs valid JSON findings."""
    prod_dir = tmp_path / "prod"
    prod_dir.mkdir()
    rules_file = prod_dir / "firestore.rules"
    rules_file.write_text(
        "service cloud.firestore {\n"
        "  match /{document=**} {\n"
        "    allow read, write: if true;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    # Run CLI via python -m scanner scan <path>
    proc = subprocess.run(
        [sys.executable, "-m", "scanner", "scan", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )

    assert proc.returncode == 0, f"CLI exited with error: {proc.stderr}"
    output_json = proc.stdout.strip()
    findings = json.loads(output_json)

    assert isinstance(findings, list)
    assert len(findings) == 1

    finding = findings[0]
    assert finding["file"] == "prod/firestore.rules"
    assert finding["line"] == 3
    assert finding["rule_id"] == "firebase-open-access"
    assert finding["severity"] == "high"
    assert finding["environment"] == "production"
    assert finding["confidence"] >= 0.5
    assert "allow read, write: if true;" in finding["message"]

    # Validate against JSON schema
    schema_path = Path(__file__).parent.parent / "schema" / "finding.schema.json"
    with open(schema_path, "r", encoding="utf-8") as sf:
        schema = json.load(sf)
    jsonschema.validate(instance=findings, schema=schema)


def test_cli_runs_clean_project(tmp_path, capsys):
    """Verify CLI produces empty JSON array on a clean project."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text("console.log('hello');", encoding="utf-8")

    exit_code = main(["scan", str(tmp_path)])
    assert exit_code == 0

    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    assert findings == []


def test_cli_exclude_pattern(tmp_path, capsys):
    """Verify CLI respects the --exclude argument."""
    vuln_dir = tmp_path / "fixtures" / "prod"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "firestore.rules").write_text(
        "service cloud.firestore {\n"
        "  match /{document=**} {\n"
        "    allow read, write: if true;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    # Without exclude, finding is present
    exit_code = main(["scan", str(tmp_path)])
    assert exit_code == 0
    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    assert len(findings) == 1

    # With exclude, finding is ignored
    exit_code_excluded = main(["scan", str(tmp_path), "--exclude", "fixtures/*"])
    assert exit_code_excluded == 0
    captured_excluded = capsys.readouterr()
    findings_excluded = json.loads(captured_excluded.out)
    assert len(findings_excluded) == 0


def test_cli_single_file_scan(tmp_path, capsys):
    """Verify CLI supports scanning a single file directly (Feature 5)."""
    single_file = tmp_path / "firestore.rules"
    single_file.write_text(
        "service cloud.firestore {\n"
        "  match /{document=**} {\n"
        "    allow read, write: if true;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    exit_code = main(["scan", str(single_file)])
    assert exit_code == 0
    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    assert len(findings) == 1
    assert findings[0]["file"] == "firestore.rules"
