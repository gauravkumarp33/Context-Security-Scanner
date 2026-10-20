from pathlib import Path
from typing import List, Union
from scanner.analyzer import classify_project
from scanner.models import Finding
from scanner.rules import run_rules


def scan_project(root: Union[str, Path]) -> List[Finding]:
    """
    Scan a repository root path by classifying file environments and running security rules.
    Returns a list of Finding objects conforming to the contract.
    """
    project_root = Path(root).resolve()
    classifications = classify_project(project_root)
    files = [project_root / rel_path for rel_path in classifications.keys()]
    return run_rules(project_root=project_root, files=files, classifications=classifications)