import pytest
from scanner.classifier import classify_environment
from scanner.models import EnvClassification


def test_classify_production_environment():
    """Verify that production paths and files return 'production' with high confidence float."""
    for path in ["deploy/prod_config.yaml", "docker-compose.prod.yml", "prod/server.py"]:
        res = classify_environment(path)
        assert isinstance(res, EnvClassification)
        assert res.environment == "production"
        assert isinstance(res.confidence, float)
        assert res.confidence >= 0.8
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
        assert res.confidence >= 0.8
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


def test_classify_environment_tuple_compatibility():
    """Verify tuple unpacking works on EnvClassification for backward compatibility."""
    env, conf, evidence = classify_environment("tests/sample.py")
    assert env == "local-testing"
    assert isinstance(conf, float)
    assert isinstance(evidence, list)