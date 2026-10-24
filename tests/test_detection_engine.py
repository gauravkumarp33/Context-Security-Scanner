import json
from pathlib import Path
from unittest.mock import patch
import jsonschema
import pytest

from scanner.models import Environment, Finding, Severity
from scanner.rules import (
    GitleaksDetector,
    RegexDetector,
    RuleDefinition,
    RuleValidationError,
    SemgrepDetector,
    load_all_rules,
    load_rules_from_yaml,
    run_rules,
)

SCHEMA_PATH = Path(__file__).parent.parent / "schema" / "finding.schema.json"


@pytest.fixture
def schema():
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# --- 1. Rule Loader Validation Tests ---

def test_rule_loader_validates_successfully(tmp_path):
    rule_yaml = tmp_path / "valid_rule.yaml"
    rule_yaml.write_text(
        """rules:
  - id: secret-fake-test
    title: Fake Secret Rule
    severity: high
    message: Fake secret detected.
    recommendation: Do not hardcode fake secrets.
    engine: regex
    pattern: "FAKE_SECRET_[A-Z0-9]{8}"
    file_globs:
      - "*.txt"
""",
        encoding="utf-8",
    )
    rules = load_rules_from_yaml(rule_yaml)
    assert len(rules) == 1
    assert rules[0].id == "secret-fake-test"
    assert rules[0].severity == Severity.HIGH
    assert rules[0].engine == "regex"


def test_rule_loader_missing_required_field_raises(tmp_path):
    rule_yaml = tmp_path / "invalid_missing.yaml"
    rule_yaml.write_text(
        """rules:
  - id: bad-rule
    title: Bad Rule
    # missing severity, message, etc.
    engine: regex
    pattern: "xyz"
    file_globs: ["*"]
""",
        encoding="utf-8",
    )
    with pytest.raises(RuleValidationError, match="missing required field"):
        load_rules_from_yaml(rule_yaml)


def test_rule_loader_invalid_severity_raises(tmp_path):
    rule_yaml = tmp_path / "invalid_sev.yaml"
    rule_yaml.write_text(
        """rules:
  - id: bad-sev
    title: Bad Sev
    severity: ultra-critical
    message: Msg
    recommendation: Rec
    engine: regex
    pattern: "xyz"
    file_globs: ["*"]
""",
        encoding="utf-8",
    )
    with pytest.raises(RuleValidationError, match="Invalid severity"):
        load_rules_from_yaml(rule_yaml)


def test_rule_loader_invalid_engine_raises(tmp_path):
    rule_yaml = tmp_path / "invalid_eng.yaml"
    rule_yaml.write_text(
        """rules:
  - id: bad-engine
    title: Bad Engine
    severity: low
    message: Msg
    recommendation: Rec
    engine: magic
    pattern: "xyz"
    file_globs: ["*"]
""",
        encoding="utf-8",
    )
    with pytest.raises(RuleValidationError, match="Invalid engine"):
        load_rules_from_yaml(rule_yaml)


# --- 2. Positive & Negative Rule Test Cases ---

# Secret Values used for testing (all obviously fake, assembled at runtime to avoid push protection scanners)
FAKE_AWS_KEY = "AK" + "IA" + "IOSFODNN7FAKEKEY"
FAKE_GH_TOKEN = "gh" + "p_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
FAKE_STRIPE_KEY = "sk_" + "live_" + "1234567890abcdefghijklmnopqr"
FAKE_PRIVATE_KEY = "-----" + "BEGIN RSA " + "PRIVATE KEY-----\n" + "MIIEfakefakefake==\n" + "-----" + "END RSA " + "PRIVATE KEY-----"
FAKE_DB_URL = "postgresql://myuser:supersecretpass999@db.internal:5432/proddb"
FAKE_API_KEY = "s3cr3t_v@lu3_999!"

ALL_FAKE_SECRETS = [
    FAKE_AWS_KEY,
    FAKE_GH_TOKEN,
    FAKE_STRIPE_KEY,
    "MIIEfakefakefake==",
    "supersecretpass999",
    FAKE_API_KEY,
]


def test_rule_secret_aws_access_key(tmp_path):
    # Positive
    pos = tmp_path / "aws_pos.py"
    pos.write_text(f'AWS_KEY = "{FAKE_AWS_KEY}"\n', encoding="utf-8")
    # Negative: placeholder ignored
    neg = tmp_path / "aws_neg.py"
    placeholder_aws = "AK" + "IA" + "EXAMPLEKEYCHANGEME"
    neg.write_text(f'AWS_KEY = "{placeholder_aws}"\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    aws_findings = [f for f in findings if f.rule_id == "secret-aws-access-key"]
    assert len(aws_findings) == 1
    assert aws_findings[0].file == "aws_pos.py"
    assert aws_findings[0].severity == Severity.CRITICAL


def test_rule_secret_github_token(tmp_path):
    # Positive
    pos = tmp_path / "gh_pos.py"
    pos.write_text(f'TOKEN = "{FAKE_GH_TOKEN}"\n', encoding="utf-8")
    # Negative: placeholder ignored
    neg = tmp_path / "gh_neg.py"
    placeholder_gh = "gh" + "p_" + "changemeplaceholderxxxxxxxxx123456"
    neg.write_text(f'TOKEN = "{placeholder_gh}"\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    gh_findings = [f for f in findings if f.rule_id == "secret-github-token"]
    assert len(gh_findings) == 1
    assert gh_findings[0].file == "gh_pos.py"
    assert gh_findings[0].severity == Severity.HIGH


def test_rule_secret_stripe_key(tmp_path):
    # Positive
    pos = tmp_path / "stripe_pos.py"
    pos.write_text(f'STRIPE = "{FAKE_STRIPE_KEY}"\n', encoding="utf-8")
    # Negative: placeholder
    neg = tmp_path / "stripe_neg.py"
    placeholder_stripe = "sk_" + "test_" + "placeholderchangeme0000000000"
    neg.write_text(f'STRIPE = "{placeholder_stripe}"\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    stripe_findings = [f for f in findings if f.rule_id == "secret-stripe-key"]
    assert len(stripe_findings) == 1
    assert stripe_findings[0].file == "stripe_pos.py"
    assert stripe_findings[0].severity == Severity.HIGH


def test_rule_secret_private_key(tmp_path):
    # Positive
    pos = tmp_path / "priv_pos.pem"
    pos.write_text(FAKE_PRIVATE_KEY, encoding="utf-8")
    # Negative: public key
    neg = tmp_path / "priv_neg.pem"
    neg.write_text("-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n-----END PUBLIC KEY-----", encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    key_findings = [f for f in findings if f.rule_id == "secret-private-key"]
    assert len(key_findings) == 1
    assert key_findings[0].file == "priv_pos.pem"
    assert key_findings[0].severity == Severity.CRITICAL


def test_rule_secret_db_connection_string(tmp_path):
    # Positive
    pos = tmp_path / "db_pos.py"
    pos.write_text(f'URL = "{FAKE_DB_URL}"\n', encoding="utf-8")
    # Negative: placeholder password
    neg = tmp_path / "db_neg.py"
    neg.write_text('URL = "postgresql://myuser:changeme@localhost:5432/testdb"\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    db_findings = [f for f in findings if f.rule_id == "secret-db-connection-string"]
    assert len(db_findings) == 1
    assert db_findings[0].file == "db_pos.py"
    assert db_findings[0].severity == Severity.CRITICAL


def test_rule_secret_generic_password(tmp_path):
    # Positive
    pos = tmp_path / "gen_pos.py"
    pos.write_text(f'api_key = "{FAKE_API_KEY}"\n', encoding="utf-8")
    # Negative: placeholder
    neg = tmp_path / "gen_neg.py"
    neg.write_text('api_key = "changeme"\npassword = "xxx"\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    gen_findings = [f for f in findings if f.rule_id == "secret-generic-password"]
    assert len(gen_findings) == 1
    assert gen_findings[0].file == "gen_pos.py"
    assert gen_findings[0].severity == Severity.MEDIUM


def test_rule_code_sql_injection(tmp_path):
    # Positive: f-string formatting inside execute
    pos = tmp_path / "sql_pos.py"
    pos.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n', encoding="utf-8")
    # Negative: parameterized query
    neg = tmp_path / "sql_neg.py"
    neg.write_text('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    sql_findings = [f for f in findings if f.rule_id == "code-sql-injection"]
    assert len(sql_findings) == 1
    assert sql_findings[0].file == "sql_pos.py"
    assert sql_findings[0].severity == Severity.HIGH


def test_rule_code_eval_exec(tmp_path):
    # Positive
    pos = tmp_path / "eval_pos.py"
    pos.write_text('eval(user_payload)\n', encoding="utf-8")
    # Negative: json.loads
    neg = tmp_path / "eval_neg.py"
    neg.write_text('json.loads(user_payload)\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    eval_findings = [f for f in findings if f.rule_id == "code-eval-exec"]
    assert len(eval_findings) == 1
    assert eval_findings[0].file == "eval_pos.py"


def test_rule_code_subprocess_shell(tmp_path):
    # Positive
    pos = tmp_path / "subp_pos.py"
    pos.write_text('subprocess.run(user_cmd, shell=True)\n', encoding="utf-8")
    # Negative
    neg = tmp_path / "subp_neg.py"
    neg.write_text('subprocess.run(["ls", "-l"], shell=False)\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    subp_findings = [f for f in findings if f.rule_id == "code-subprocess-shell"]
    assert len(subp_findings) == 1
    assert subp_findings[0].file == "subp_pos.py"


def test_rule_code_hardcoded_secret_key(tmp_path):
    # Positive
    pos = tmp_path / "app_pos.py"
    pos.write_text('SECRET_KEY = "insecure-hardcoded-secret-key-value"\n', encoding="utf-8")
    # Negative
    neg = tmp_path / "app_neg.py"
    neg.write_text('SECRET_KEY = os.environ.get("SECRET_KEY")\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    sk_findings = [f for f in findings if f.rule_id == "code-hardcoded-secret-key"]
    assert len(sk_findings) == 1
    assert sk_findings[0].file == "app_pos.py"


def test_rule_code_debug_mode(tmp_path):
    # Positive
    pos = tmp_path / "debug_pos.py"
    pos.write_text('DEBUG = True\n', encoding="utf-8")
    # Negative
    neg = tmp_path / "debug_neg.py"
    neg.write_text('DEBUG = False\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    dbg_findings = [f for f in findings if f.rule_id == "code-debug-mode"]
    assert len(dbg_findings) == 1
    assert dbg_findings[0].file == "debug_pos.py"


def test_rule_code_tls_verify_disabled(tmp_path):
    # Positive
    pos = tmp_path / "tls_pos.py"
    pos.write_text('requests.get("https://internal.service", verify=False)\n', encoding="utf-8")
    # Negative
    neg = tmp_path / "tls_neg.py"
    neg.write_text('requests.get("https://internal.service", verify=True)\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    tls_findings = [f for f in findings if f.rule_id == "code-tls-verify-disabled"]
    assert len(tls_findings) == 1
    assert tls_findings[0].file == "tls_pos.py"


def test_rule_code_weak_password_hash(tmp_path):
    # Positive
    pos = tmp_path / "hash_pos.py"
    pos.write_text('token = hashlib.md5(pwd.encode()).hexdigest()\n', encoding="utf-8")
    # Negative
    neg = tmp_path / "hash_neg.py"
    neg.write_text('token = hashlib.sha256(pwd.encode()).hexdigest()\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    hash_findings = [f for f in findings if f.rule_id == "code-weak-password-hash"]
    assert len(hash_findings) == 1
    assert hash_findings[0].file == "hash_pos.py"


def test_rule_code_cors_wildcard(tmp_path):
    # Positive
    pos = tmp_path / "cors_pos.py"
    pos.write_text('CORS(app, origins="*")\n', encoding="utf-8")
    # Negative
    neg = tmp_path / "cors_neg.py"
    neg.write_text('CORS(app, origins="https://secure.corp")\n', encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    cors_findings = [f for f in findings if f.rule_id == "code-cors-wildcard"]
    assert len(cors_findings) == 1
    assert cors_findings[0].file == "cors_pos.py"


def test_rule_firebase_auth_without_authorization(tmp_path):
    # Positive
    pos = tmp_path / "auth_pos.rules"
    pos.write_text("allow read, write: if request.auth != null;\n", encoding="utf-8")
    # Negative
    neg = tmp_path / "auth_neg.rules"
    neg.write_text("allow read: if request.auth.uid == userId;\n", encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    fb_findings = [f for f in findings if f.rule_id == "firebase-auth-without-authorization"]
    assert len(fb_findings) == 1
    assert fb_findings[0].file == "auth_pos.rules"
    assert fb_findings[0].severity == Severity.MEDIUM


def test_rule_config_docker_db_port_exposed(tmp_path):
    # Positive
    pos = tmp_path / "docker-compose.yml"
    pos.write_text("services:\n  db:\n    ports:\n      - '5432:5432'\n", encoding="utf-8")
    # Negative
    neg = tmp_path / "docker-compose.safe.yml"
    neg.write_text("services:\n  db:\n    ports:\n      - '127.0.0.1:5432:5432'\n", encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    db_port_findings = [f for f in findings if f.rule_id == "config-docker-db-port-exposed"]
    assert len(db_port_findings) == 1
    assert db_port_findings[0].file == "docker-compose.yml"
    assert db_port_findings[0].severity == Severity.HIGH


def test_rule_config_db_password_env(tmp_path):
    # Positive
    pos = tmp_path / "docker-compose.env.yml"
    pos.write_text("services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: 'supersecretprodpass123'\n", encoding="utf-8")
    # Negative
    neg = tmp_path / "docker-compose.safeenv.yml"
    neg.write_text("services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: 'changeme'\n", encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    env_findings = [f for f in findings if f.rule_id == "config-db-password-env"]
    assert len(env_findings) == 1
    assert env_findings[0].file == "docker-compose.env.yml"


def test_rule_config_docker_container_root(tmp_path):
    # Positive
    pos = tmp_path / "Dockerfile.pos"
    pos.write_text("FROM alpine\nUSER root\nCMD ['sh']\n", encoding="utf-8")
    # Negative
    neg = tmp_path / "Dockerfile.neg"
    neg.write_text("FROM alpine\nUSER nonroot\nCMD ['sh']\n", encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    root_findings = [f for f in findings if f.rule_id == "config-docker-container-root"]
    assert len(root_findings) == 1
    assert root_findings[0].file == "Dockerfile.pos"


def test_rule_config_github_actions_pull_request_target(tmp_path):
    # Positive
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    pos = wf_dir / "pr_target.yml"
    pos.write_text("name: Test\non:\n  pull_request_target:\njobs:\n  t:\n    runs-on: ubuntu-latest\n", encoding="utf-8")
    # Negative
    neg = wf_dir / "pr.yml"
    neg.write_text("name: Test\non:\n  pull_request:\njobs:\n  t:\n    runs-on: ubuntu-latest\n", encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    prt_findings = [f for f in findings if f.rule_id == "config-github-actions-pull-request-target"]
    assert len(prt_findings) == 1
    assert prt_findings[0].file == ".github/workflows/pr_target.yml"


def test_rule_config_github_actions_unpinned(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    # Positive: unpinned tag
    pos = wf_dir / "unpinned.yml"
    pos.write_text("steps:\n  - uses: actions/checkout@v3\n", encoding="utf-8")
    # Negative: pinned to full 40-char SHA
    neg = wf_dir / "pinned.yml"
    neg.write_text("steps:\n  - uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab\n", encoding="utf-8")

    findings = run_rules(project_root=tmp_path, files=[pos, neg])
    unpinned_findings = [f for f in findings if f.rule_id == "config-github-actions-unpinned"]
    assert len(unpinned_findings) == 1
    assert unpinned_findings[0].file == ".github/workflows/unpinned.yml"


# --- 3. Secret Value Sanitization Assertion Test ---

def test_no_secret_value_in_findings_output(tmp_path):
    """Assert that NO secret value ever appears in any finding field, log or message."""
    test_file = tmp_path / "all_secrets.py"
    test_file.write_text(
        f"""
AWS_KEY = "{FAKE_AWS_KEY}"
GH_TOKEN = "{FAKE_GH_TOKEN}"
STRIPE = "{FAKE_STRIPE_KEY}"
DB_URL = "{FAKE_DB_URL}"
api_key = "{FAKE_API_KEY}"
""",
        encoding="utf-8",
    )

    findings = run_rules(project_root=tmp_path, files=[test_file])
    assert len(findings) >= 4

    for f in findings:
        finding_dict = f.to_dict()
        full_json = json.dumps(finding_dict)
        for secret in ALL_FAKE_SECRETS:
            assert secret not in f.message, f"Secret value leaked in message: {secret}"
            assert secret not in f.recommendation, f"Secret value leaked in recommendation: {secret}"
            assert secret not in full_json, f"Secret value leaked in finding json: {secret}"


# --- 4. Missing Tool Graceful Continuation Test ---

def test_missing_tools_does_not_crash(tmp_path):
    """Assert that when semgrep or gitleaks is not installed, the runner skips them and continues without crashing."""
    code_file = tmp_path / "vuln.py"
    code_file.write_text('eval("1+1")\n', encoding="utf-8")

    with patch("scanner.rules.is_semgrep_available", return_value=False), \
         patch("scanner.rules.is_gitleaks_available", return_value=False):
        findings = run_rules(project_root=tmp_path, files=[code_file])

    assert len(findings) == 1
    assert findings[0].rule_id == "code-eval-exec"


# --- 5. Schema Validation Test for All Output ---

def test_findings_validate_against_schema(tmp_path, schema):
    """Verify that all findings validate against schema/finding.schema.json."""
    app_file = tmp_path / "app.py"
    app_file.write_text(
        f"""
DEBUG = True
SECRET_KEY = "django-insecure-testkey12345"
eval(payload)
AWS_KEY = "{FAKE_AWS_KEY}"
""",
        encoding="utf-8",
    )

    findings = run_rules(project_root=tmp_path, files=[app_file])
    findings_dicts = [f.to_dict() for f in findings]

    assert len(findings_dicts) >= 3
    jsonschema.validate(instance=findings_dicts, schema=schema)


# --- 6. Clean Project Yields Zero Findings ---

def test_clean_project_gives_zero_findings(tmp_path):
    """Verify that clean codebase with secure practices returns 0 findings."""
    clean_py = tmp_path / "server.py"
    clean_py.write_text(
        """import os
import json
import hashlib

def hash_pass(password: str) -> str:
    salt = os.urandom(16)
    return hashlib.sha256(salt + password.encode()).hexdigest()

def get_data(payload: str):
    return json.loads(payload)

DEBUG = False
SECRET_KEY = os.environ.get("APP_SECRET_KEY")
""",
        encoding="utf-8",
    )

    clean_rules = tmp_path / "firestore.rules"
    clean_rules.write_text(
        """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
""",
        encoding="utf-8",
    )

    findings = run_rules(project_root=tmp_path, files=[clean_py, clean_rules])
    assert len(findings) == 0


# --- 7. Semgrep Unmapped Rule Message Redaction & Malformed Line Numbers ---

def test_semgrep_unmapped_rule_does_not_leak_secret(tmp_path):
    """Assert Semgrep results with unmapped check_id never leak secrets in extra.message."""
    target_file = tmp_path / "app.py"
    target_file.write_text("API_SECRET = 'supersecret'\n", encoding="utf-8")

    fake_secret = "AKIA_FAKE_SECRET_TEST_12345"
    mock_semgrep_results = [
        {
            "check_id": "unmapped-custom-semgrep-rule",
            "start": {"line": 1},
            "extra": {
                "message": f"Hardcoded secret leaked in extra.message: {fake_secret}",
                "lines": f"API_SECRET = '{fake_secret}'",
            },
        }
    ]

    dummy_semgrep_rule = RuleDefinition(
        id="semgrep-generic-rule",
        title="Generic Semgrep Rule",
        severity=Severity.HIGH,
        message="Known semgrep rule message.",
        recommendation="Fix issue.",
        engine="semgrep",
        pattern="",
        file_globs=["*"],
    )

    detector = SemgrepDetector([dummy_semgrep_rule])
    with patch("scanner.rules.is_semgrep_available", return_value=True), \
         patch("scanner.rules.run_semgrep", return_value=mock_semgrep_results):
        findings = detector.detect(target_file, target_file.read_text(encoding="utf-8"))

    assert len(findings) == 1
    raw_finding = findings[0]
    assert raw_finding.message == "Semgrep security issue."
    assert fake_secret not in raw_finding.message
    assert fake_secret not in raw_finding.recommendation

    finding = Finding(
        file="app.py",
        line=raw_finding.line,
        rule_id=raw_finding.rule_id,
        severity=raw_finding.severity,
        message=raw_finding.message,
        environment=Environment.PRODUCTION,
        confidence=0.9,
        recommendation=raw_finding.recommendation,
    )
    finding_dict = finding.to_dict()
    finding_json = json.dumps(finding_dict)

    for field_val in finding_dict.values():
        assert fake_secret not in str(field_val)
    assert fake_secret not in finding_json


def test_detectors_malformed_line_numbers_safe(tmp_path):
    """Assert detectors handle malformed line numbers (e.g. string 'abc') without crashing."""
    target_file = tmp_path / "test_file.py"
    target_file.write_text("print('hello')\n", encoding="utf-8")

    # 1. Gitleaks with StartLine="abc"
    gl_rule = RuleDefinition(
        id="gl-test-rule",
        title="Gitleaks Rule",
        severity=Severity.HIGH,
        message="Secret found.",
        recommendation="Rotate secret.",
        engine="gitleaks",
        pattern="",
        file_globs=["*"],
    )
    gl_detector = GitleaksDetector([gl_rule])
    mock_gl_results = [{"RuleID": "gl-test-rule", "StartLine": "abc"}]

    with patch("scanner.rules.is_gitleaks_available", return_value=True), \
         patch("scanner.rules.run_gitleaks", return_value=mock_gl_results):
        gl_findings = gl_detector.detect(target_file, target_file.read_text(encoding="utf-8"))

    assert len(gl_findings) == 1
    assert gl_findings[0].line >= 1

    # 2. Semgrep with line="abc"
    sg_rule = RuleDefinition(
        id="sg-test-rule",
        title="Semgrep Rule",
        severity=Severity.MEDIUM,
        message="Code issue.",
        recommendation="Fix code.",
        engine="semgrep",
        pattern="",
        file_globs=["*"],
    )
    sg_detector = SemgrepDetector([sg_rule])
    mock_sg_results = [{"check_id": "sg-test-rule", "start": {"line": "abc"}}]

    with patch("scanner.rules.is_semgrep_available", return_value=True), \
         patch("scanner.rules.run_semgrep", return_value=mock_sg_results):
        sg_findings = sg_detector.detect(target_file, target_file.read_text(encoding="utf-8"))

    assert len(sg_findings) == 1
    assert sg_findings[0].line >= 1

