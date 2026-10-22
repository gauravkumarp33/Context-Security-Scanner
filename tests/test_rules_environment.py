import json
from pathlib import Path
from unittest.mock import patch
import jsonschema
import pytest

from scanner.analyzer import classify_project
from scanner.models import Environment, Severity
from scanner.rules import run_rules


@pytest.fixture
def repo_root():
    return Path(__file__).parent.parent


@pytest.fixture
def vulnerable_fixture_path(repo_root):
    return repo_root / "tests" / "fixtures" / "vulnerable_project"


def test_classifier_failure_falls_back_to_unknown(tmp_path):
    """Verify that any exception in classifier gracefully falls back to unknown environment and 0.0 confidence."""
    rules_file = tmp_path / "firestore.rules"
    rules_file.write_text("allow read, write: if true;\n", encoding="utf-8")

    with patch("scanner.rules.classify_environment", side_effect=RuntimeError("Classifier engine crashed")):
        findings = run_rules(
            project_root=tmp_path,
            files=[rules_file],
            classifications=None,
        )

    assert len(findings) == 1
    f = findings[0]
    assert f.environment == Environment.UNKNOWN
    assert f.confidence == 0.0
    assert f.rule_id == "firebase-open-access"


def test_single_file_run_rules_equals_full_scan(vulnerable_fixture_path):
    """Verify that a single-file run_rules gives the same environment, confidence, and severity as a full scan."""
    rules_file = vulnerable_fixture_path / "prod" / "firestore.rules"
    assert rules_file.exists()

    # 1. Full scan approach (classifications computed via classify_project across repo)
    full_classifications = classify_project(vulnerable_fixture_path)
    full_findings = run_rules(
        project_root=vulnerable_fixture_path,
        files=[rules_file],
        classifications=full_classifications,
    )

    # 2. Single-file scan approach (classifications=None, lazy context and single file)
    single_findings = run_rules(
        project_root=vulnerable_fixture_path,
        files=[rules_file],
        classifications=None,
    )

    assert len(full_findings) == 1
    assert len(single_findings) == 1

    f_full = full_findings[0]
    f_single = single_findings[0]

    assert f_single.file == f_full.file
    assert f_single.line == f_full.line
    assert f_single.rule_id == f_full.rule_id
    assert f_single.environment == f_full.environment
    assert f_single.confidence == f_full.confidence
    assert f_single.severity == f_full.severity


def test_single_file_result_equals_classify_project(vulnerable_fixture_path):
    """Verify that single-file run_rules environment and confidence equal classify_project for that file."""
    rules_file = vulnerable_fixture_path / "prod" / "firestore.rules"
    rel_posix = "prod/firestore.rules"

    project_classifications = classify_project(vulnerable_fixture_path)
    expected_classification = project_classifications[rel_posix]

    findings = run_rules(
        project_root=vulnerable_fixture_path,
        files=[rules_file],
        classifications=None,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.environment.value == expected_classification.environment
    assert f.confidence == expected_classification.confidence


def test_rules_output_validates_against_schema(vulnerable_fixture_path, repo_root):
    """Verify that run_rules output strictly conforms to schema/finding.schema.json."""
    rules_file = vulnerable_fixture_path / "prod" / "firestore.rules"
    findings = run_rules(
        project_root=vulnerable_fixture_path,
        files=[rules_file],
        classifications=None,
    )

    findings_dicts = [f.to_dict() for f in findings]

    schema_file = repo_root / "schema" / "finding.schema.json"
    with open(schema_file, "r", encoding="utf-8") as sf:
        schema = json.load(sf)

    jsonschema.validate(instance=findings_dicts, schema=schema)
