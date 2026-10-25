import json
from pathlib import Path
import pytest
from scanner.analyzer import classify_project
from scanner.classifier import classify_environment
from scanner.context import load_project_context
from scanner.models import EnvClassification


def test_classify_production_environment():
    """Verify that path segment signals return 'production' with 0.5-0.6 confidence."""
    for path in ["deploy/prod_config.yaml", "docker-compose.prod.yml", "prod/server.py"]:
        res = classify_environment(path)
        assert isinstance(res, EnvClassification)
        assert res.environment == "production"
        assert isinstance(res.confidence, float)
        assert 0.5 <= res.confidence <= 0.6
        assert isinstance(res.evidence, list)
        assert len(res.evidence) > 0


def test_classify_local_testing_environment():
    """Verify that test and dev paths return 'local-testing' (never 'test' or 'development')."""
    for path in ["tests/fixtures/test_sample.py", "config/dev_settings.json", "src/auth.test.ts"]:
        res = classify_environment(path)
        assert isinstance(res, EnvClassification)
        assert res.environment == "local-testing"
        assert res.environment not in ("test", "development")
        assert isinstance(res.confidence, float)
        assert 0.6 <= res.confidence <= 0.8
        assert isinstance(res.evidence, list)
        assert len(res.evidence) > 0


def test_classify_ambiguous_environment_is_unknown():
    """Verify that conflicting signals (e.g. prod + test segments) resolve to 'unknown' with low confidence."""
    for path in ["tests/prod_deploy.yaml", "prod/test_api.py"]:
        res = classify_environment(path)
        assert isinstance(res, EnvClassification)
        assert res.environment == "unknown"
        assert isinstance(res.confidence, float)
        assert res.confidence <= 0.3
        assert isinstance(res.evidence, list)


def test_classify_product_service_is_not_production():
    """Verify that 'product_service.py' is not classified as production due to substring matching."""
    for path in ["src/product_service.py", "product_service.py"]:
        res = classify_environment(path)
        assert isinstance(res, EnvClassification)
        assert res.environment != "production"
        assert res.environment == "unknown"


def test_classify_unknown_environment():
    """Verify that files with no environment signals return 'unknown' with low confidence."""
    res = classify_environment("scanner/utils.py")
    assert isinstance(res, EnvClassification)
    assert res.environment == "unknown"
    assert isinstance(res.confidence, float)
    assert res.confidence <= 0.3
    assert len(res.evidence) > 0


def test_classify_environment_tuple_compatibility():
    """Verify tuple unpacking works on EnvClassification for backward compatibility."""
    env, conf, evidence = classify_environment("tests/sample.py")
    assert env == "local-testing"
    assert isinstance(conf, float)
    assert isinstance(evidence, list)


def test_firebase_json_deployed_rules_is_production(tmp_path):
    """Verify rules deployed in firebase.json are classified as production with high confidence (0.9+)."""
    firebase_cfg = {
        "firestore": {"rules": "firestore.rules"},
        "storage": {"rules": "storage.rules"},
    }
    (tmp_path / "firebase.json").write_text(json.dumps(firebase_cfg), encoding="utf-8")
    (tmp_path / "firestore.rules").write_text("rules_version = '2';", encoding="utf-8")
    (tmp_path / "storage.rules").write_text("rules_version = '2';", encoding="utf-8")

    classifications = classify_project(tmp_path)
    res = classifications["firestore.rules"]

    assert res.environment == "production"
    assert res.confidence >= 0.9
    assert any("firebase.json" in e for e in res.evidence)


def test_same_file_under_tests_fixtures_not_deployed_is_local_testing(tmp_path):
    """Verify rules file under tests/fixtures not deployed is local-testing with confidence 0.7-0.8."""
    # Deployed file at root
    firebase_cfg = {"firestore": {"rules": "firestore.rules"}}
    (tmp_path / "firebase.json").write_text(json.dumps(firebase_cfg), encoding="utf-8")
    (tmp_path / "firestore.rules").write_text("rules_version = '2';", encoding="utf-8")

    # Non-deployed file under tests/fixtures
    fixtures_dir = tmp_path / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    test_rules = fixtures_dir / "firestore.rules"
    test_rules.write_text("rules_version = '2';", encoding="utf-8")

    classifications = classify_project(tmp_path)
    res = classifications["tests/fixtures/firestore.rules"]

    assert res.environment == "local-testing"
    assert 0.7 <= res.confidence <= 0.8
    assert any("tests" in e or "fixtures" in e for e in res.evidence)


def test_local_only_file_deployed_is_production_with_conflict_evidence(tmp_path):
    """Verify local-only file (via tests/ path or config) that is deployed is classified production with 0.95 confidence and CONFLICT evidence."""
    # Deploying a file that resides in tests/
    firebase_cfg = {"firestore": {"rules": "tests/firestore.rules"}}
    (tmp_path / "firebase.json").write_text(json.dumps(firebase_cfg), encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "firestore.rules").write_text("rules_version = '2';", encoding="utf-8")

    classifications = classify_project(tmp_path)
    res = classifications["tests/firestore.rules"]

    assert res.environment == "production"
    assert res.confidence == 0.95
    assert any("CONFLICT: declared local-only but deployed to production" in e for e in res.evidence)


def test_no_signals_is_unknown(tmp_path):
    """Verify file with no clear signals is classified as unknown with confidence 0.2-0.3 and non-empty evidence."""
    f = tmp_path / "unmarked_helper.py"
    f.write_text("def helper(): pass", encoding="utf-8")

    classifications = classify_project(tmp_path)
    res = classifications["unmarked_helper.py"]

    assert res.environment == "unknown"
    assert 0.2 <= res.confidence <= 0.3
    assert len(res.evidence) > 0


def test_malformed_firebase_json_does_not_crash(tmp_path):
    """Verify malformed firebase.json records evidence warning and does not crash scanner."""
    (tmp_path / "firebase.json").write_text("{ broken json: missing quote }", encoding="utf-8")
    (tmp_path / "firestore.rules").write_text("rules_version = '2';", encoding="utf-8")

    ctx = load_project_context(tmp_path)
    assert any("malformed firebase.json" in e for e in ctx.project_evidence)

    classifications = classify_project(tmp_path)
    assert "firestore.rules" in classifications
    assert isinstance(classifications["firestore.rules"], EnvClassification)


def test_single_file_classification_matches_full_project_result(tmp_path):
    """Verify single-file classification with root produces identical result to full project scan."""
    firebase_cfg = {"firestore": {"rules": "firestore.rules"}}
    (tmp_path / "firebase.json").write_text(json.dumps(firebase_cfg), encoding="utf-8")
    (tmp_path / "firestore.rules").write_text("rules_version = '2';", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_api.py").write_text("def test(): pass", encoding="utf-8")

    full_res = classify_project(tmp_path)

    single_rules = classify_environment("firestore.rules", root=tmp_path)
    single_test = classify_environment("tests/test_api.py", root=tmp_path)

    assert single_rules.environment == full_res["firestore.rules"].environment
    assert single_rules.confidence == full_res["firestore.rules"].confidence
    assert single_rules.evidence == full_res["firestore.rules"].evidence

    assert single_test.environment == full_res["tests/test_api.py"].environment
    assert single_test.confidence == full_res["tests/test_api.py"].confidence
    assert single_test.evidence == full_res["tests/test_api.py"].evidence


def test_compose_services_classify_referenced_files_and_keep_evidence(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Dockerfile.prod").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "prod.env").write_text("MODE=prod\n", encoding="utf-8")
    (tmp_path / "docker-compose.prod.yml").write_text(
        "services:\n  api:\n    build:\n      context: ./app\n      dockerfile: Dockerfile.prod\n    env_file: prod.env\n    volumes:\n      - ./app:/srv/app\n",
        encoding="utf-8",
    )
    (tmp_path / "tests" / "mock").mkdir(parents=True)
    (tmp_path / "tests" / "mock" / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    (tmp_path / "docker-compose.test.yml").write_text(
        "services:\n  test:\n    build: ./tests/mock\n    env_file: tests/test.env\n    volumes:\n      - ./tests/fixtures:/fixtures\n",
        encoding="utf-8",
    )

    ctx = load_project_context(tmp_path)
    prod, prod_evidence = ctx.is_deployed("app/Dockerfile.prod")
    local, local_evidence = ctx.is_configured_local_only("tests/mock")
    assert prod and any("Dockerfile referenced by production service" in e for e in prod_evidence)
    assert ctx.is_deployed("app/Dockerfile.prod")[0]
    assert ctx.is_deployed("app/source.py")[0]
    assert ctx.is_deployed("prod.env")[0]
    assert ctx.is_deployed("app")[0]
    assert local and any("Build path referenced by local/test service" in e for e in local_evidence)
    assert ctx.is_configured_local_only("tests/mock/Dockerfile")[0]
    assert ctx.is_configured_local_only("tests/test.env")[0]
    assert ctx.is_configured_local_only("tests/fixtures")[0]


def test_github_branch_trigger_alone_is_not_deployment_evidence(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        "name: CI\non:\n  push:\n    branches: [main]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    ctx = load_project_context(tmp_path)
    assert ctx.is_deployed("Dockerfile")[0] is False


def test_github_deployment_job_links_existing_deployment_files(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (tmp_path / "firestore.rules").write_text("rules_version = '2';\n", encoding="utf-8")
    (workflow_dir / "deploy.yml").write_text(
        "name: Deploy\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    environment: production\n    steps:\n      - run: firebase deploy --only firestore:rules\n      - run: echo firestore.rules\n",
        encoding="utf-8",
    )
    deployed, evidence = load_project_context(tmp_path).is_deployed("firestore.rules")
    assert deployed
    assert any("deployment job" in item for item in evidence)
