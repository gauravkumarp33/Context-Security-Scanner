import os
from pathlib import Path
from typing import Dict, List, Union
from scanner.classifier import classify_environment
from scanner.models import EnvClassification

EXCLUDED_DIRS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build'}


def is_excluded_dir(dir_name: str) -> bool:
    name_lower = dir_name.lower()
    if name_lower in EXCLUDED_DIRS:
        return True
    if name_lower.startswith("venv") or name_lower.startswith(".venv"):
        return True
    return False


def analyze_repository(repo_path: str) -> List[str]:
    file_list = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not is_excluded_dir(d)]
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), repo_path)
            file_list.append(rel_path)
    return file_list


def classify_project(root: Union[str, Path]) -> Dict[str, EnvClassification]:
    """
    Classify environments for all scanned files across a project repository.
    Returns a dictionary of POSIX relative paths to EnvClassification objects,
    skipping excluded directories (.git, venvs, node_modules, build, dist).
    """
    project_root = Path(root).resolve()
    classifications: Dict[str, EnvClassification] = {}

    for current_dir, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not is_excluded_dir(d)]
        for file in files:
            full_path = Path(current_dir) / file
            rel_posix = full_path.relative_to(project_root).as_posix()
            classifications[rel_posix] = classify_environment(rel_posix)

    return classifications