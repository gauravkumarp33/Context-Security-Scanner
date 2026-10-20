import re
from pathlib import Path
from typing import Dict, List, Optional, Union
from scanner.models import EnvClassification, Environment, Finding, Severity

FIREBASE_OPEN_ACCESS_PATTERN = re.compile(
    r"allow\s+(?:read\s*,\s*write|write\s*,\s*read)\s*:\s*if\s+true\s*;"
)


def run_rules(
    project_root: Path,
    files: List[Path],
    classifications: Optional[Dict[str, Union[EnvClassification, tuple]]] = None,
) -> List[Finding]:
    """
    Entry point for running security detection rules against files in a project.

    Args:
        project_root: Root path of the codebase.
        files: List of file paths to scan.
        classifications: Map of relative file paths to EnvClassification (or M1's raw tuple).
                         Missing classification defaults to 'unknown' environment and 0.0 confidence.

    Returns:
        List of Finding objects conforming to the shared contract.
    """
    classifications = classifications or {}
    project_root = Path(project_root).resolve()
    normalized_classifications: Dict[str, EnvClassification] = {}

    for path_str, raw_val in classifications.items():
        norm_key = Path(path_str).as_posix()
        if isinstance(raw_val, EnvClassification):
            normalized_classifications[norm_key] = raw_val
        elif isinstance(raw_val, (tuple, list)):
            normalized_classifications[norm_key] = EnvClassification.from_tuple(tuple(raw_val))
        elif isinstance(raw_val, dict):
            normalized_classifications[norm_key] = EnvClassification(**raw_val)
        else:
            normalized_classifications[norm_key] = EnvClassification(
                environment=Environment.UNKNOWN.value,
                confidence=0.0,
                evidence=[],
            )

    findings: List[Finding] = []

    for file_item in files:
        file_path = Path(file_item)
        if file_path.is_absolute():
            try:
                rel_key = file_path.relative_to(project_root).as_posix()
            except ValueError:
                rel_key = file_path.as_posix()
            full_path = file_path
        else:
            rel_key = file_path.as_posix()
            full_path = project_root / file_path

        classification = normalized_classifications.get(
            rel_key,
            EnvClassification(
                environment=Environment.UNKNOWN.value,
                confidence=0.0,
                evidence=["Missing classification; defaulted to unknown"],
            ),
        )

        if full_path.suffix == ".rules" or full_path.name.endswith(".rules"):
            if full_path.is_file():
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line_text in enumerate(f, start=1):
                            if FIREBASE_OPEN_ACCESS_PATTERN.search(line_text):
                                findings.append(
                                    Finding(
                                        file=rel_key,
                                        line=line_num,
                                        rule_id="firebase-open-access",
                                        severity=Severity.HIGH,
                                        message="Insecure Firestore rules: open read and write access granted ('allow read, write: if true;').",
                                        environment=classification.environment,
                                        confidence=classification.confidence,
                                        recommendation="Restrict Firestore access rules by enforcing authentication and authorization checks instead of 'if true;'.",
                                    )
                                )
                except OSError:
                    continue

    return findings
