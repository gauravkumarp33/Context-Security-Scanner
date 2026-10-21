import fnmatch
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from scanner.classifier import classify_environment
from scanner.models import EnvClassification, ProjectFile

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

EXCLUDED_DIRS = DEFAULT_EXCLUDED_DIRS


def is_excluded_dir(dir_name: str) -> bool:
    name_lower = dir_name.lower()
    if name_lower in DEFAULT_EXCLUDED_DIRS:
        return True
    if name_lower.startswith("venv") or name_lower.startswith(".venv"):
        return True
    return False


def determine_kind(rel_path: str, filename: str) -> str:
    """
    Tag a file with a kind based on its path and name:
    - docker: Dockerfile*, docker-compose*.yml/yaml
    - ci: .github/workflows/*.yml/yaml
    - firebase: firebase.json, .firebaserc, *.rules
    - config: *.env, .env*, *.yaml, *.yml, *.json, *.toml, *.ini, *.conf
    - code: *.py, *.js, *.ts
    - other: everything else
    """
    rel_lower = rel_path.replace("\\", "/").lower()
    name_lower = filename.lower()

    # 1. docker: Dockerfile*, docker-compose*.yml/yaml
    if name_lower.startswith("dockerfile") or (
        name_lower.startswith("docker-compose")
        and (name_lower.endswith(".yml") or name_lower.endswith(".yaml"))
    ):
        return "docker"

    # 2. ci: .github/workflows/*.yml/yaml
    if (
        rel_lower.startswith(".github/workflows/")
        or "/.github/workflows/" in rel_lower
    ) and (name_lower.endswith(".yml") or name_lower.endswith(".yaml")):
        return "ci"

    # 3. firebase: firebase.json, .firebaserc, *.rules
    if (
        name_lower == "firebase.json"
        or name_lower == ".firebaserc"
        or name_lower.endswith(".rules")
    ):
        return "firebase"

    # 4. config: *.env, .env*, *.yaml, *.yml, *.json, *.toml, *.ini, *.conf
    if (
        name_lower.endswith(".env")
        or name_lower.startswith(".env")
        or name_lower.endswith(".yaml")
        or name_lower.endswith(".yml")
        or name_lower.endswith(".json")
        or name_lower.endswith(".toml")
        or name_lower.endswith(".ini")
        or name_lower.endswith(".conf")
    ):
        return "config"

    # 5. code: *.py, *.js, *.ts
    if (
        name_lower.endswith(".py")
        or name_lower.endswith(".js")
        or name_lower.endswith(".ts")
    ):
        return "code"

    # 6. other: everything else
    return "other"


def _is_excluded_by_user(rel_posix: str, name: str, exclude_patterns: List[str]) -> bool:
    for pat in exclude_patterns:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(name.lower(), pat.lower()):
            return True
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix.lower(), pat.lower()):
            return True
        clean_pat = pat.rstrip("/")
        if fnmatch.fnmatch(rel_posix, clean_pat) or fnmatch.fnmatch(rel_posix.lower(), clean_pat.lower()):
            return True
        if fnmatch.fnmatch(rel_posix, f"{clean_pat}/*") or fnmatch.fnmatch(rel_posix.lower(), f"{clean_pat.lower()}/*"):
            return True
    return False


def _is_binary_file(file_path: Union[str, Path]) -> bool:
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except OSError:
        return True


def discover_files(
    root: Union[str, Path],
    exclude: Optional[Union[List[str], Set[str], Tuple[str, ...], str]] = None,
) -> List[ProjectFile]:
    """
    Discover all non-binary files <= 1 MB in a repository or for a single file,
    tagging each with a kind and skipping excluded directories/patterns and symlinks.
    Results are sorted deterministically by POSIX relative path.
    """
    if exclude is None:
        user_excludes: List[str] = []
    elif isinstance(exclude, str):
        user_excludes = [exclude]
    else:
        user_excludes = list(exclude)

    root_path = Path(root)

    if not root_path.exists():
        return []

    # Never follow symlinks
    if os.path.islink(root_path):
        return []

    # Single file support
    if root_path.is_file():
        try:
            size = root_path.stat().st_size
        except OSError:
            return []

        if size > 1024 * 1024:
            return []

        if _is_binary_file(root_path):
            return []

        rel_posix = root_path.name if root_path.is_absolute() else root_path.as_posix()
        if _is_excluded_by_user(rel_posix, root_path.name, user_excludes):
            return []

        kind = determine_kind(rel_posix, root_path.name)
        return [ProjectFile(path=rel_posix, kind=kind, size=size)]

    # Directory walk
    discovered: List[ProjectFile] = []
    root_resolved = root_path.resolve()

    for current_dir, dirs, files in os.walk(root_resolved, followlinks=False):
        # Prune excluded directories and symlinks in-place
        dirs_to_keep = []
        for d in dirs:
            dir_full = os.path.join(current_dir, d)
            if os.path.islink(dir_full):
                continue
            dir_rel = os.path.relpath(dir_full, root_resolved).replace("\\", "/")
            if is_excluded_dir(d) or _is_excluded_by_user(dir_rel, d, user_excludes):
                continue
            dirs_to_keep.append(d)
        dirs[:] = dirs_to_keep

        for f in files:
            file_full = os.path.join(current_dir, f)
            if os.path.islink(file_full):
                continue

            file_rel = os.path.relpath(file_full, root_resolved).replace("\\", "/")
            if user_excludes and _is_excluded_by_user(file_rel, f, user_excludes):
                continue

            try:
                size = os.path.getsize(file_full)
            except OSError:
                continue

            if size > 1024 * 1024:
                continue

            if _is_binary_file(file_full):
                continue

            kind = determine_kind(file_rel, f)
            discovered.append(ProjectFile(path=file_rel, kind=kind, size=size))

    # Sort output by path so results are deterministic
    discovered.sort(key=lambda pf: pf.path)
    return discovered


def analyze_repository(repo_path: str) -> List[str]:
    file_list = []
    for root, dirs, files in os.walk(repo_path, followlinks=False):
        dirs[:] = [d for d in dirs if not is_excluded_dir(d)]
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), repo_path)
            file_list.append(rel_path)
    return file_list


def classify_project(
    root: Union[str, Path],
    exclude: Optional[Union[List[str], Set[str], Tuple[str, ...], str]] = None,
) -> Dict[str, EnvClassification]:
    """
    Classify environments for all scanned files across a project repository.
    Returns a dictionary of POSIX relative paths to EnvClassification objects,
    using discover_files so discovery and classification never disagree.
    """
    project_files = discover_files(root, exclude=exclude)
    return {pf.path: classify_environment(pf.path) for pf in project_files}