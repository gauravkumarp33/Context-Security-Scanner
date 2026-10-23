from pathlib import Path
from typing import List, Optional, Set, Tuple, Union
from scanner.analyzer import classify_project, discover_files
from scanner.classifier import classify_environment
from scanner.context import load_project_context
from scanner.models import Finding
from scanner.rules import run_rules


def _find_enclosing_project_root(file_path: Path) -> Path:
    """Find the nearest ancestor directory that looks like a project root."""
    indicators = {
        "firebase.json",
        ".firebaserc",
        "scanner.config.json",
        ".git",
        "pyproject.toml",
        "package.json",
    }
    for parent in file_path.parents:
        if any((parent / ind).exists() for ind in indicators):
            return parent
    return file_path.parent


def scan_project(
    root: Union[str, Path],
    exclude: Optional[Union[List[str], Set[str], Tuple[str, ...], str]] = None,
) -> List[Finding]:
    """
    Scan a repository root path or a single file by classifying file environments and running security rules.
    Returns a list of Finding objects conforming to the contract.
    """
    target = Path(root).resolve()

    if target.is_file():
        project_root = _find_enclosing_project_root(target)
        try:
            rel_path = target.relative_to(project_root).as_posix()
        except ValueError:
            rel_path = target.name

        context = load_project_context(project_root)
        classification = classify_environment(rel_path, root=project_root, context=context)
        classifications = {rel_path: classification}
        return run_rules(project_root=project_root, files=[target], classifications=classifications)

    project_files = discover_files(target, exclude=exclude)
    classifications = classify_project(target, exclude=exclude)

    files = [target / pf.path for pf in project_files]
    return run_rules(project_root=target, files=files, classifications=classifications)
