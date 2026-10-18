import pytest
from scanner.classifier import classify_environment

def test_classify_test_environment():
    env, conf, _ = classify_environment("tests/fixtures/test_sample.py")
    assert env == "test"
    assert conf == "high"

def test_classify_production_environment():
    env, conf, _ = classify_environment("deploy/prod_config.yaml")
    assert env == "production"
    assert conf == "high"

def test_classify_development_environment():
    env, conf, _ = classify_environment("config/dev_settings.json")
    assert env == "development"
    assert conf == "medium"

def test_classify_unknown_environment():
    env, conf, _ = classify_environment("scanner/utils.py")
    assert env == "unknown"
    assert conf == "low"