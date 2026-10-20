import re
from pathlib import Path, PurePosixPath
from typing import List, Set, Union
from scanner.models import EnvClassification, Environment

PROD_SEGMENTS: Set[str] = {
    "prod",
    "production",
    "deploy",
    "deployment",
}

LOCAL_TESTING_SEGMENTS: Set[str] = {
    "test",
    "tests",
    "testing",
    "spec",
    "specs",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "dev",
    "development",
    "local",
}


def _extract_segments(file_path: Union[str, Path]) -> List[str]:
    """Extract distinct path tokens/segments from directory parts and filename."""
    path_str = str(file_path).replace("\\", "/")
    parts = PurePosixPath(path_str).parts

    segments: List[str] = []
    for part in parts:
        # Split each path component (folder or filename) by non-alphanumeric delimiters (. - _)
        sub_tokens = [tok.lower() for tok in re.split(r"[._\-]+", part) if tok]
        segments.extend(sub_tokens)
    return segments


def classify_environment(file_path: Union[str, Path]) -> EnvClassification:
    """
    Classify the execution environment for a given file path based on path segments.

    Returns an EnvClassification with only one of three allowed environments:
    - 'production'
    - 'local-testing'
    - 'unknown'
    """
    segments = _extract_segments(file_path)

    matched_prod: List[str] = []
    matched_local: List[str] = []

    for seg in segments:
        if seg in PROD_SEGMENTS and seg not in matched_prod:
            matched_prod.append(f"Path segment '{seg}' indicates production environment")
        if seg in LOCAL_TESTING_SEGMENTS and seg not in matched_local:
            matched_local.append(f"Path segment '{seg}' indicates local-testing environment")

    # Ambiguous signal if both production and local/testing segments exist
    if matched_prod and matched_local:
        return EnvClassification(
            environment=Environment.UNKNOWN.value,
            confidence=0.2,
            evidence=["Ambiguous environment: path matches both production and local-testing signals"]
            + matched_prod
            + matched_local,
        )

    if matched_prod:
        return EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.9,
            evidence=matched_prod,
        )

    if matched_local:
        return EnvClassification(
            environment=Environment.LOCAL_TESTING.value,
            confidence=0.9,
            evidence=matched_local,
        )

    # No clear signal
    return EnvClassification(
        environment=Environment.UNKNOWN.value,
        confidence=0.2,
        evidence=["No clear environment signals found in path"],
    )


def classify_environment_tuple(file_path: Union[str, Path]) -> tuple:
    """Thin tuple-compatibility wrapper returning (environment, confidence, evidence)."""
    ec = classify_environment(file_path)
    return (ec.environment, ec.confidence, ec.evidence)