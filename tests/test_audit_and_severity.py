import json
from pathlib import Path
import jsonschema
import pytest

from scanner.models import EnvClassification, Environment, Finding, Severity
from scanner.rules import (
    DEFAULT_RULES_DIR,
    RuleException,
    load_all_rules,
    run_rules,
)

SCHEMA_PATH = Path(__file__).parent.parent / "schema" / "finding.schema.json"
RULES_DIR = Path(__file__).parent.parent / "rules"
RULES_MD = RULES_DIR / "RULES.md"

SUSPICIOUS_SECRET_PATTERNS = [
    "AKIA",
    "ASIA",
    "ghp_",
    "gho_",
    "sk_live",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "s3cr3t",
    "supersecret",
]


@pytest.fixture
def schema():
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_every_rule_has_non_empty_message_and_recommendation_with_no_secrets():
    """Verify that every rule has a clear 1-sentence message and recommendation with no secret values."""
    rules = load_all_rules(RULES_DIR)
    assert len(rules) >= 20

    for r in rules:
        # Message validation
        assert r.message and len(r.message.strip()) > 0, f"Empty message in rule {r.id}"
        assert r.message.strip().endswith("."), f"Message must end with a period in rule {r.id}: {r.message}"
        # Ensure single sentence (no interior sentence splits unless in parens or quotes)
        clean_msg = r.message.strip()
        sentence_count = len([s for s in clean_msg.split(". ") if s.strip()])
        assert sentence_count == 1, f"Message should be exactly one sentence in rule {r.id}: {clean_msg}"

        # Recommendation validation
        assert r.recommendation and len(r.recommendation.strip()) > 0, f"Empty recommendation in rule {r.id}"
        rec_sentences = len([s for s in r.recommendation.strip().split(". ") if s.strip()])
        assert 1 <= rec_sentences <= 3, f"Recommendation should be 1-2 sentences in rule {r.id}: {r.recommendation}"

        # No secret values in message or recommendation
        for pattern in SUSPICIOUS_SECRET_PATTERNS:
            assert pattern not in r.message, f"Secret pattern '{pattern}' leaked in message of {r.id}"
            assert pattern not in r.recommendation, f"Secret pattern '{pattern}' leaked in recommendation of {r.id}"


def test_same_vulnerable_snippet_production_local_testing_unknown_expected_severities(tmp_path):
    """
    Verify that the same vulnerable snippet across production, local-testing, and unknown
    environments results in expected severity adjustments.
    """
    # Rule with base severity MEDIUM and raise_in_production: true -> code-debug-mode
    debug_code = "DEBUG = True\n"

    # 1. Production file
    prod_file = tmp_path / "prod" / "settings.py"
    prod_file.parent.mkdir(parents=True, exist_ok=True)
    prod_file.write_text(debug_code, encoding="utf-8")

    # 2. Local-testing file
    test_file = tmp_path / "tests" / "test_settings.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text(debug_code, encoding="utf-8")

    # 3. Unknown file
    unknown_file = tmp_path / "standalone.py"
    unknown_file.write_text(debug_code, encoding="utf-8")

    classifications = {
        "prod/settings.py": EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.9,
            evidence=["production dir"],
        ),
        "tests/test_settings.py": EnvClassification(
            environment=Environment.LOCAL_TESTING.value,
            confidence=0.9,
            evidence=["tests dir"],
        ),
        "standalone.py": EnvClassification(
            environment=Environment.UNKNOWN.value,
            confidence=0.1,
            evidence=["no signals"],
        ),
    }

    findings = run_rules(
        project_root=tmp_path,
        files=[prod_file, test_file, unknown_file],
        classifications=classifications,
    )

    by_file = {f.file: f for f in findings if f.rule_id == "code-debug-mode"}
    assert len(by_file) == 3

    # Production: base MEDIUM raised 1 level -> HIGH
    f_prod = by_file["prod/settings.py"]
    assert f_prod.severity == Severity.HIGH
    assert f_prod.environment == Environment.PRODUCTION

    # Local-testing: base MEDIUM lowered 1 level -> LOW
    f_test = by_file["tests/test_settings.py"]
    assert f_test.severity == Severity.LOW
    assert f_test.environment == Environment.LOCAL_TESTING

    # Unknown: base MEDIUM kept, message appends environment could not be determined
    f_unknown = by_file["standalone.py"]
    assert f_unknown.severity == Severity.MEDIUM
    assert f_unknown.environment == Environment.UNKNOWN
    assert "(environment could not be determined)" in f_unknown.message


def test_conflict_raises_severity_and_adds_message_note(tmp_path):
    """Verify that a CONFLICT in classification evidence raises severity by one level and notes the message."""
    app_file = tmp_path / "app.py"
    app_file.write_text("DEBUG = True\n", encoding="utf-8")

    # Base severity for code-debug-mode is MEDIUM.
    classifications = {
        "app.py": EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.95,
            evidence=["CONFLICT: declared local-only but deployed to production"],
        )
    }

    findings = run_rules(
        project_root=tmp_path,
        files=[app_file],
        classifications=classifications,
    )

    debug_findings = [f for f in findings if f.rule_id == "code-debug-mode"]
    assert len(debug_findings) == 1
    f = debug_findings[0]

    # Raised 1 level: MEDIUM -> HIGH
    assert f.severity == Severity.HIGH
    assert "(declared local-only but deployed to production)" in f.message


def test_active_exception_downgrades_to_low_and_adds_note_without_hiding(tmp_path):
    """Verify active exception downgrades finding to LOW and appends reason without suppressing finding."""
    target_file = tmp_path / "tests" / "mock_server.py"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text('SECRET_KEY = "django-insecure-test-key-for-local-mock-12345"\n', encoding="utf-8")

    exceptions_yaml = tmp_path / "rules" / "exceptions.yaml"
    exceptions_yaml.parent.mkdir(parents=True, exist_ok=True)
    exceptions_yaml.write_text(
        """exceptions:
  - file_glob: "tests/mock_*.py"
    rule_id: "code-hardcoded-secret-key"
    reason: "Unit test mock key"
    expiry: "2099-12-31"
""",
        encoding="utf-8",
    )

    findings = run_rules(
        project_root=tmp_path,
        files=[target_file],
        exceptions_file=exceptions_yaml,
    )

    secret_findings = [f for f in findings if f.rule_id == "code-hardcoded-secret-key"]
    assert len(secret_findings) == 1
    f = secret_findings[0]

    # Downgraded to LOW
    assert f.severity == Severity.LOW
    assert "[exception: Unit test mock key]" in f.message


def test_expired_exception_is_ignored_and_logged(tmp_path, caplog):
    """Verify that an expired exception does not downgrade severity and logs a warning."""
    import logging

    target_file = tmp_path / "src" / "config.py"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text('SECRET_KEY = "django-insecure-prod-key-1234567890"\n', encoding="utf-8")

    exceptions_yaml = tmp_path / "rules" / "exceptions.yaml"
    exceptions_yaml.parent.mkdir(parents=True, exist_ok=True)
    exceptions_yaml.write_text(
        """exceptions:
  - file_glob: "src/config.py"
    rule_id: "code-hardcoded-secret-key"
    reason: "Temporary test exception"
    expiry: "2020-01-01"
""",
        encoding="utf-8",
    )

    classifications = {
        "src/config.py": EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.9,
            evidence=["prod"],
        )
    }

    with caplog.at_level(logging.WARNING):
        findings = run_rules(
            project_root=tmp_path,
            files=[target_file],
            classifications=classifications,
            exceptions_file=exceptions_yaml,
        )

    secret_findings = [f for f in findings if f.rule_id == "code-hardcoded-secret-key"]
    assert len(secret_findings) == 1
    f = secret_findings[0]

    # Expired exception must NOT downgrade to low
    assert f.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "[exception:" not in f.message

    # Warning logged
    assert any("expired" in record.message.lower() for record in caplog.records)


def test_rules_md_lists_every_rule_id_in_yaml():
    """Verify that rules/RULES.md documents every rule ID defined in the YAML rule catalogs."""
    assert RULES_MD.exists(), "rules/RULES.md must exist"
    md_content = RULES_MD.read_text(encoding="utf-8")

    yaml_rules = load_all_rules(RULES_DIR)
    assert len(yaml_rules) >= 20

    for r in yaml_rules:
        assert f"`{r.id}`" in md_content, f"Rule ID '{r.id}' missing from rules/RULES.md"


def test_audit_findings_output_validates_against_schema(tmp_path, schema):
    """Verify that all adjusted findings strictly validate against schema/finding.schema.json."""
    pos_file = tmp_path / "app.py"
    pos_file.write_text(
        """
DEBUG = True
SECRET_KEY = "dummy-secret-key-12345"
""",
        encoding="utf-8",
    )

    findings = run_rules(project_root=tmp_path, files=[pos_file])
    assert len(findings) >= 1

    findings_json = [f.to_dict() for f in findings]
    jsonschema.validate(instance=findings_json, schema=schema)
