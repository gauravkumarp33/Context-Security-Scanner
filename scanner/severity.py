from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Union
from scanner.models import Environment, Severity

CONFIDENCE_THRESHOLD: float = 0.8

PRODUCTION_RAISABLE_CATEGORIES: Set[str] = {
    "debug_mode",
    "disabled_tls",
    "exposed_secret",
}

LOCAL_TESTING_LOWERABLE_CATEGORIES: Set[str] = {
    "insecure_config",
    "test_credentials",
    "public_access",
    "debug_mode",
}

RULE_CATEGORY_MAP: Dict[str, str] = {
    "firebase-open-access": "public_access",
    "firebase-auth-without-authorization": "public_access",
    "secret-aws-access-key": "exposed_secret",
    "secret-github-token": "exposed_secret",
    "secret-stripe-key": "exposed_secret",
    "secret-private-key": "exposed_secret",
    "secret-db-connection-string": "exposed_secret",
    "secret-generic-password": "exposed_secret",
    "code-debug-mode": "debug_mode",
    "code-tls-verify-disabled": "disabled_tls",
    "code-hardcoded-secret-key": "exposed_secret",
    "code-cors-wildcard": "insecure_config",
    "config-docker-db-port-exposed": "insecure_config",
    "config-db-password-env": "exposed_secret",
    "config-docker-container-root": "insecure_config",
    "config-github-actions-pull-request-target": "insecure_config",
    "config-github-actions-unpinned": "insecure_config",
}

SEVERITY_ORDER: List[Severity] = [
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _raise_severity(sev: Severity) -> Severity:
    """Raise severity by one level, capped at critical."""
    idx = SEVERITY_ORDER.index(sev)
    if idx < len(SEVERITY_ORDER) - 1:
        return SEVERITY_ORDER[idx + 1]
    return sev


def _lower_severity(sev: Severity) -> Severity:
    """Lower severity by one level, never going below low."""
    idx = SEVERITY_ORDER.index(sev)
    if idx > 0:
        return SEVERITY_ORDER[idx - 1]
    return sev


def get_rule_category(rule_id: str) -> Optional[str]:
    """Return configured category for a rule ID, or None if unmapped."""
    return RULE_CATEGORY_MAP.get(rule_id)


def adjust_severity(
    severity: Union[Severity, str],
    category: Optional[str],
    environment: Union[Environment, str],
    confidence: float,
    is_real_secret: bool = False,
) -> Severity:
    """
    Adjust severity based on context environment, category, and classification confidence.

    Rules:
    - low < medium < high < critical. Never go below low or above critical.
    - If category is None or unmapped, return original severity unchanged.
    - Confidence below 0.8 is treated as unknown for adjustment only.
    - production: keep severity, or raise ONE level for raisable categories. Cap at critical.
    - local-testing: lower by at most ONE level, only if confidence >= 0.8 AND category
      is lowerable. Real-looking secrets (is_real_secret=True) are NEVER lowered.
    - unknown: NEVER lowers severity.
    """
    # Normalize severity
    if isinstance(severity, Severity):
        current_sev = severity
    elif isinstance(severity, str):
        current_sev = Severity(severity.strip().lower())
    else:
        raise ValueError(f"Invalid severity type: {type(severity)}")

    # Unmapped categories are never adjusted
    if not category:
        return current_sev

    # Normalize environment
    if isinstance(environment, Environment):
        env_val = environment.value
    elif isinstance(environment, str):
        env_val = environment.strip().lower()
    else:
        env_val = Environment.UNKNOWN.value

    # Confidence below 0.8 is treated as unknown for adjustment only
    try:
        conf_val = float(confidence)
    except (ValueError, TypeError):
        conf_val = 0.0

    # Apply environment adjustment policies
    if env_val == Environment.PRODUCTION.value:
        if category in PRODUCTION_RAISABLE_CATEGORIES:
            return _raise_severity(current_sev)
        return current_sev

    if env_val == Environment.LOCAL_TESTING.value:
        # Confidence below 0.8 is treated as unknown for adjustment only (never lowers)
        if conf_val < CONFIDENCE_THRESHOLD:
            return current_sev
        if is_real_secret:
            return current_sev
        if category in LOCAL_TESTING_LOWERABLE_CATEGORIES:
            return _lower_severity(current_sev)
        return current_sev

    # unknown: NEVER lowers severity
    return current_sev


def adjust_severity_for_rule(
    severity: Union[Severity, str],
    rule_id: str,
    environment: Union[Environment, str],
    confidence: float,
    is_real_secret: bool = False,
) -> Severity:
    """Convenience helper looking up rule category before adjusting severity."""
    cat = get_rule_category(rule_id)
    return adjust_severity(
        severity=severity,
        category=cat,
        environment=environment,
        confidence=confidence,
        is_real_secret=is_real_secret,
    )
