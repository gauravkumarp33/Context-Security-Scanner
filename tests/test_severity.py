import pytest
from scanner.models import Environment, Severity
from scanner.severity import (
    adjust_severity,
    adjust_severity_for_rule,
    get_rule_category,
)


def test_unknown_never_lowers():
    """Verify that environment 'unknown' never lowers severity even with 1.0 confidence."""
    assert adjust_severity(
        severity=Severity.HIGH,
        category="insecure_config",
        environment=Environment.UNKNOWN,
        confidence=1.0,
    ) == Severity.HIGH

    assert adjust_severity(
        severity=Severity.CRITICAL,
        category="test_credentials",
        environment="unknown",
        confidence=0.9,
    ) == Severity.CRITICAL


def test_confidence_below_point_eight_never_lowers():
    """Verify that confidence below 0.8 in local-testing is treated as unknown and never lowers."""
    assert adjust_severity(
        severity=Severity.HIGH,
        category="insecure_config",
        environment=Environment.LOCAL_TESTING,
        confidence=0.79,
    ) == Severity.HIGH

    assert adjust_severity(
        severity=Severity.MEDIUM,
        category="test_credentials",
        environment="local-testing",
        confidence=0.5,
    ) == Severity.MEDIUM


def test_confidence_exactly_point_eight_lowers():
    """Verify boundary condition: confidence exactly 0.8 in local-testing lowers by one level."""
    assert adjust_severity(
        severity=Severity.HIGH,
        category="insecure_config",
        environment=Environment.LOCAL_TESTING,
        confidence=0.8,
    ) == Severity.MEDIUM

    assert adjust_severity(
        severity=Severity.CRITICAL,
        category="test_credentials",
        environment=Environment.LOCAL_TESTING,
        confidence=0.8,
    ) == Severity.HIGH


def test_real_secret_never_lowered():
    """Verify that is_real_secret=True prevents lowering even with high confidence in local-testing."""
    assert adjust_severity(
        severity=Severity.HIGH,
        category="test_credentials",
        environment=Environment.LOCAL_TESTING,
        confidence=0.95,
        is_real_secret=True,
    ) == Severity.HIGH

    assert adjust_severity(
        severity=Severity.CRITICAL,
        category="insecure_config",
        environment="local-testing",
        confidence=1.0,
        is_real_secret=True,
    ) == Severity.CRITICAL


def test_production_raises_exactly_one_level():
    """Verify that production raises raisable categories by exactly one level."""
    # LOW -> MEDIUM
    assert adjust_severity(
        severity=Severity.LOW,
        category="disabled_tls",
        environment=Environment.PRODUCTION,
        confidence=0.9,
    ) == Severity.MEDIUM

    # MEDIUM -> HIGH
    assert adjust_severity(
        severity=Severity.MEDIUM,
        category="debug_mode",
        environment=Environment.PRODUCTION,
        confidence=0.95,
    ) == Severity.HIGH

    # HIGH -> CRITICAL
    assert adjust_severity(
        severity=Severity.HIGH,
        category="exposed_secret",
        environment="production",
        confidence=0.85,
    ) == Severity.CRITICAL


def test_critical_stays_critical():
    """Verify that raising in production is capped at critical."""
    assert adjust_severity(
        severity=Severity.CRITICAL,
        category="exposed_secret",
        environment=Environment.PRODUCTION,
        confidence=0.99,
    ) == Severity.CRITICAL


def test_local_testing_never_goes_below_low():
    """Verify that lowering in local-testing is bounded and never drops below low."""
    assert adjust_severity(
        severity=Severity.LOW,
        category="insecure_config",
        environment=Environment.LOCAL_TESTING,
        confidence=0.9,
    ) == Severity.LOW


def test_unmapped_rule_unchanged():
    """Verify that an unmapped rule or missing category is never adjusted in any environment."""
    # Unmapped rule ID
    assert get_rule_category("unmapped-custom-rule-xyz") is None

    assert adjust_severity_for_rule(
        severity=Severity.HIGH,
        rule_id="unmapped-custom-rule-xyz",
        environment=Environment.PRODUCTION,
        confidence=0.95,
    ) == Severity.HIGH

    assert adjust_severity_for_rule(
        severity=Severity.HIGH,
        rule_id="unmapped-custom-rule-xyz",
        environment=Environment.LOCAL_TESTING,
        confidence=0.95,
    ) == Severity.HIGH

    assert adjust_severity(
        severity=Severity.HIGH,
        category=None,
        environment=Environment.PRODUCTION,
        confidence=0.95,
    ) == Severity.HIGH


def test_firebase_open_access_policy():
    """Verify exact policy for firebase-open-access (public_access).

    - production: stays HIGH
    - unknown: stays HIGH
    - local-testing with confidence < 0.8: stays HIGH
    - local-testing with confidence >= 0.8: lowers to MEDIUM
    """
    # Production stays HIGH
    assert adjust_severity_for_rule(
        severity=Severity.HIGH,
        rule_id="firebase-open-access",
        environment=Environment.PRODUCTION,
        confidence=0.95,
    ) == Severity.HIGH

    # Unknown stays HIGH
    assert adjust_severity_for_rule(
        severity=Severity.HIGH,
        rule_id="firebase-open-access",
        environment=Environment.UNKNOWN,
        confidence=0.9,
    ) == Severity.HIGH

    # Confidence below 0.8 in local-testing stays HIGH
    assert adjust_severity_for_rule(
        severity=Severity.HIGH,
        rule_id="firebase-open-access",
        environment=Environment.LOCAL_TESTING,
        confidence=0.79,
    ) == Severity.HIGH

    # Confidence >= 0.8 in local-testing lowers to MEDIUM
    assert adjust_severity_for_rule(
        severity=Severity.HIGH,
        rule_id="firebase-open-access",
        environment=Environment.LOCAL_TESTING,
        confidence=0.8,
    ) == Severity.MEDIUM

