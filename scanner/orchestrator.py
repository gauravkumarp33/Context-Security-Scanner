from pathlib import Path
from typing import List, Optional, Set, Tuple, Union
from scanner.analyzer import classify_project, discover_files
from scanner.models import Finding
from scanner.rules import run_rules


def scan_project(
    root: Union[str, Path],
    exclude: Optional[Union[List[str], Set[str], Tuple[str, ...], str]] = None,
) -> List[Finding]:
    """
    Scan a repository root path by classifying file environments and running security rules.
    Returns a list of Finding objects conforming to the contract.
    """
    target = Path(root).resolve()
    project_files = discover_files(target, exclude=exclude)
    classifications = classify_project(target, exclude=exclude)

    project_root = target if target.is_dir() else target.parent
    files = [project_root / pf.path for pf in project_files]
    return run_rules(project_root=project_root, files=files, classifications=classifications)