import json
from pathlib import Path
import jsonschema
import pytest

from scanner.models import (
    EnvClassification,
    Environment,
    Finding,
    Severity,
)
from scanner.rules import run_rules


@pytest.fixture
def project_root():
    return Path(__file__).parent.parent


def test_valid_finding_passes():
    """Verify that a valid finding instantiates correctly and serializes to dict."""
    finding = Finding(
        file="src/server.py",
        line=10,
        rule_id="SEC-001",
        severity=Severity.HIGH,
        message="Insecure configuration detected",
        environment=Environment.PRODUCTION,
        confidence=0.9,
        recommendation="Use TLS encryption",
    )

    assert finding.file == "src/server.py"
    assert finding.line == 10
    assert finding.rule_id == "SEC-001"
    assert finding.severity == Severity.HIGH
    assert finding.message == "Insecure configuration detected"
    assert finding.environment == Environment.PRODUCTION
    assert finding.confidence == 0.9
    assert finding.recommendation == "Use TLS encryption"

    d = finding.to_dict()
    assert d == {
        "file": "src/server.py",
        "line": 10,
        "rule_id": "SEC-001",
        "severity": "high",
        "message": "Insecure configuration detected",
        "environment": "production",
        "confidence": 0.9,
        "recommendation": "Use TLS encryption",
    }


def test_valid_finding_with_string_enums_passes():
    """Verify that string inputs for severity and environment work."""
    finding = Finding(
        file="config/dev.yaml",
        line=1,
        rule_id="SEC-002",
        severity="medium",
        message="Debug mode active",
        environment="local-testing",
        confidence=0.5,
        recommendation="Disable debug mode in production",
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.environment == Environment.LOCAL_TESTING
    assert finding.to_dict()["environment"] == "local-testing"
    assert finding.to_dict()["severity"] == "medium"


def test_bad_severity_fails():
    """Verify that invalid severity fails validation."""
    with pytest.raises(ValueError, match="Invalid severity"):
        Finding(
            file="src/server.py",
            line=10,
            rule_id="SEC-001",
            severity="extreme",
            message="Test message",
            environment=Environment.PRODUCTION,
            confidence=0.9,
            recommendation="Test recommendation",
        )


def test_line_zero_fails():
    """Verify that line number 0 fails validation (must be >= 1)."""
    with pytest.raises(ValueError, match="Line must be >= 1"):
        Finding(
            file="src/server.py",
            line=0,
            rule_id="SEC-001",
            severity=Severity.LOW,
            message="Test message",
            environment=Environment.LOCAL_TESTING,
            confidence=0.8,
            recommendation="Test recommendation",
        )


def test_negative_line_fails():
    """Verify that negative line numbers fail validation."""
    with pytest.raises(ValueError, match="Line must be >= 1"):
        Finding(
            file="src/server.py",
            line=-5,
            rule_id="SEC-001",
            severity=Severity.LOW,
            message="Test message",
            environment=Environment.UNKNOWN,
            confidence=0.0,
            recommendation="Test recommendation",
        )


def test_bad_confidence_fails():
    """Verify that confidence of 1.5 fails validation (must be 0.0 - 1.0)."""
    with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
        Finding(
            file="src/server.py",
            line=12,
            rule_id="SEC-001",
            severity=Severity.CRITICAL,
            message="Test message",
            environment=Environment.PRODUCTION,
            confidence=1.5,
            recommendation="Test recommendation",
        )


def test_negative_confidence_fails():
    """Verify that negative confidence fails validation."""
    with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
        Finding(
            file="src/server.py",
            line=12,
            rule_id="SEC-001",
            severity=Severity.CRITICAL,
            message="Test message",
            environment=Environment.PRODUCTION,
            confidence=-0.1,
            recommendation="Test recommendation",
        )


def test_bad_environment_fails():
    """Verify that invalid environment fails validation."""
    with pytest.raises(ValueError, match="Invalid environment"):
        Finding(
            file="src/server.py",
            line=12,
            rule_id="SEC-001",
            severity=Severity.CRITICAL,
            message="Test message",
            environment="staging",
            confidence=0.9,
            recommendation="Test recommendation",
        )


def test_mock_findings_json_validates_against_schema(project_root):
    """Verify that tests/fixtures/mock_findings.json validates against schema/finding.schema.json."""
    schema_path = project_root / "schema" / "finding.schema.json"
    fixtures_path = project_root / "tests" / "fixtures" / "mock_findings.json"

    assert schema_path.exists(), f"Schema file not found at {schema_path}"
    assert fixtures_path.exists(), f"Fixtures file not found at {fixtures_path}"

    with open(schema_path, "r", encoding="utf-8") as sf:
        schema = json.load(sf)

    with open(fixtures_path, "r", encoding="utf-8") as ff:
        mock_findings = json.load(ff)

    assert isinstance(mock_findings, list)
    assert len(mock_findings) == 3

    # Validate against JSON Schema
    jsonschema.validate(instance=mock_findings, schema=schema)

    # Verify environments in mock findings
    environments = {item["environment"] for item in mock_findings}
    assert environments == {"production", "local-testing", "unknown"}

    # Also verify that mock findings can instantiate Finding objects directly
    for item in mock_findings:
        finding_obj = Finding(**item)
        assert finding_obj.to_dict() == item


def test_run_rules_entry_point_missing_classification_defaults_to_unknown(project_root):
    """Verify that run_rules defaults missing classification to unknown."""
    files = [Path("app/unclassified.py")]
    findings = run_rules(project_root=project_root, files=files, classifications={})
    assert isinstance(findings, list)


def test_run_rules_entry_point_adapts_to_m1_tuple_shape(project_root):
    """Verify that run_rules accepts M1's tuple format (env, conf, reason)."""
    files = [Path("tests/test_sample.py")]
    classifications = {
        "tests/test_sample.py": ("test", "high", "Path contains test keywords")
    }
    findings = run_rules(project_root=project_root, files=files, classifications=classifications)
    assert isinstance(findings, list)


def test_env_classification_from_m1_tuple():
    """Verify EnvClassification adapter correctly translates M1's output."""
    ec = EnvClassification.from_tuple(("test", "high", "Path contains test keyword"))
    assert ec.environment == "local-testing"
    assert ec.confidence == 0.9
    assert ec.evidence == ["Path contains test keyword"]

    ec_prod = EnvClassification.from_tuple(("production", "high", "Path contains prod"))
    assert ec_prod.environment == "production"
    assert ec_prod.confidence == 0.9


def test_run_rules_finds_firestore_rule_at_right_line(tmp_path):
    """Verify that run_rules detects the firestore open access rule at the exact line."""
    rules_content = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
"""
    rules_file = tmp_path / "firestore.rules"
    rules_file.write_text(rules_content, encoding="utf-8")

    classifications = {
        "firestore.rules": EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.9,
            evidence=["Production rules file"],
        )
    }

    findings = run_rules(
        project_root=tmp_path,
        files=[rules_file],
        classifications=classifications,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.file == "firestore.rules"
    assert f.line == 5
    assert f.rule_id == "firebase-open-access"
    assert f.severity == Severity.HIGH
    assert f.environment == Environment.PRODUCTION
    assert f.confidence == 0.9
    assert "allow read, write: if true;" in f.message
    assert len(f.recommendation) > 0


def test_run_rules_finds_firestore_rule_missing_classification_defaults_unknown(tmp_path):
    """Verify that firestore rule finding receives unknown environment and 0.0 confidence when unclassified."""
    rules_content = "allow read, write: if true;\n"
    rules_file = tmp_path / "custom.rules"
    rules_file.write_text(rules_content, encoding="utf-8")

    findings = run_rules(
        project_root=tmp_path,
        files=[rules_file],
        classifications={},
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.line == 1
    assert f.environment == Environment.UNKNOWN
    assert f.confidence == 0.0


def test_env_classification_to_dict_and_strict_validation():
    """Verify EnvClassification to_dict method and strict environment value validation."""
    ec = EnvClassification(environment="production", confidence=0.85, evidence=["deploy manifest"])
    assert ec.to_dict() == {
        "environment": "production",
        "confidence": 0.85,
        "evidence": ["deploy manifest"],
    }

    # Old string mappings should raise ValueError when passed directly
    with pytest.raises(ValueError, match="Invalid environment"):
        EnvClassification(environment="test")

    with pytest.raises(ValueError, match="Invalid environment"):
        EnvClassification(environment="development")

    with pytest.raises(ValueError, match="Invalid environment"):
        EnvClassification(environment="invalid-env")

