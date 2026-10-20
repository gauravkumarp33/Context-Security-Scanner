from pathlib import Path
from typing import Dict, List, Optional, Union
from scanner.models import EnvClassification, Environment, Finding


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

    for file_path in files:
        # Determine relative path key
        if file_path.is_absolute() and project_root in file_path.parents:
            rel_key = file_path.relative_to(project_root).as_posix()
        else:
            rel_key = Path(file_path).as_posix()

        # Fallback to unknown if missing classification
        classification = normalized_classifications.get(
            rel_key,
            EnvClassification(
                environment=Environment.UNKNOWN.value,
                confidence=0.0,
                evidence=["Missing classification; defaulted to unknown"],
            ),
        )

        # In Feature 0, the contract entry point is established.
        # Future features will evaluate semgrep / regex rules using `classification`.

    return findings
