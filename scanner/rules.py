import re
from pathlib import Path
from typing import Dict, List, Optional, Union
from scanner.classifier import classify_environment
from scanner.context import ProjectContext, load_project_context
from scanner.models import EnvClassification, Environment, Finding, Severity
from scanner.severity import adjust_severity_for_rule

FIREBASE_OPEN_ACCESS_PATTERN = re.compile(
    r"allow\s+(?:read\s*,\s*write|write\s*,\s*read)\s*:\s*if\s+true\s*;"
)
FIREBASE_OPEN_ACCESS_BASE_SEVERITY = Severity.HIGH


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
                         If None, missing files are classified using classify_environment with cached context.

    Returns:
        List of Finding objects conforming to the shared contract.
    """
    project_root = Path(project_root).resolve()
    normalized_classifications: Dict[str, EnvClassification] = {}

    if classifications is not None:
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
    ctx: Optional[ProjectContext] = None
    classification_cache: Dict[str, EnvClassification] = {}

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

        # Resolve classification
        if classifications is not None:
            classification = normalized_classifications.get(
                rel_key,
                EnvClassification(
                    environment=Environment.UNKNOWN.value,
                    confidence=0.0,
                    evidence=["Missing classification; defaulted to unknown"],
                ),
            )
        else:
            if rel_key in classification_cache:
                classification = classification_cache[rel_key]
            else:
                try:
                    if ctx is None:
                        ctx = load_project_context(project_root)
                    resolved_target = full_path.resolve() if full_path.exists() else full_path
                    classification = classify_environment(
                        resolved_target,
                        root=project_root,
                        context=ctx,
                    )
                    if not isinstance(classification, EnvClassification):
                        classification = EnvClassification(
                            environment=Environment.UNKNOWN.value,
                            confidence=0.0,
                            evidence=["classifier_error"],
                        )
                except Exception:
                    classification = EnvClassification(
                        environment=Environment.UNKNOWN.value,
                        confidence=0.0,
                        evidence=["classifier_error"],
                    )
                classification_cache[rel_key] = classification

        if full_path.suffix == ".rules" or full_path.name.endswith(".rules"):
            if full_path.is_file():
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line_text in enumerate(f, start=1):
                            if FIREBASE_OPEN_ACCESS_PATTERN.search(line_text):
                                rule_id = "firebase-open-access"
                                final_severity = adjust_severity_for_rule(
                                    severity=FIREBASE_OPEN_ACCESS_BASE_SEVERITY,
                                    rule_id=rule_id,
                                    environment=classification.environment,
                                    confidence=classification.confidence,
                                )
                                findings.append(
                                    Finding(
                                        file=rel_key,
                                        line=line_num,
                                        rule_id=rule_id,
                                        severity=final_severity,
                                        message="Insecure Firestore rules: open read and write access granted ('allow read, write: if true;').",
                                        environment=classification.environment,
                                        confidence=classification.confidence,
                                        recommendation="Restrict Firestore access rules by enforcing authentication and authorization checks instead of 'if true;'.",
                                    )
                                )
                except OSError:
                    continue

    # Deterministic output (sort by file, line, rule_id)
    findings.sort(key=lambda item: (item.file, item.line, item.rule_id))
    return findings
