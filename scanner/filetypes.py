import os
import re
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Set, Union

from scanner.analyzer import discover_files

ALL_TAGS: Set[str] = {
    "docker",
    "compose",
    "ci",
    "github-actions",
    "gitlab-ci",
    "circleci",
    "bitbucket-pipelines",
    "azure-pipelines",
    "kubernetes",
    "terraform",
    "env",
    "yaml",
    "json",
    "toml",
    "firebase",
    "config",
    "code",
    "secret-file",
}

BACKUP_EXTENSIONS = (".bak", ".tmp", ".backup", ".old", ".swp")

CODE_EXTENSIONS = (
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".bash",
    ".go",
    ".java",
    ".php",
    ".rb",
    ".cs",
)

SECRET_FILE_NAMES = {
    "id_rsa",
    "id_ed25519",
    "id_dsa",
    "id_ecdsa",
    ".npmrc",
    ".pypirc",
    ".netrc",
}

SECRET_FILE_EXTENSIONS = (
    ".pem",
    ".key",
    ".crt",
    ".pfx",
    ".p12",
)


def _sniff_kubernetes(file_path: Path) -> bool:
    """Safely check the first 4 KB of a YAML file for Kubernetes apiVersion and kind."""
    try:
        if not file_path.is_file():
            return False
        with open(file_path, "rb") as f:
            chunk = f.read(4096)
        chunk_lower = chunk.lower()
        has_api_version = re.search(rb"(?m)^\s*apiversion\s*:", chunk_lower) is not None
        has_kind = re.search(rb"(?m)^\s*kind\s*:", chunk_lower) is not None
        return has_api_version and has_kind
    except (OSError, UnicodeDecodeError):
        return False


def get_file_types(path: Union[str, Path]) -> Set[str]:
    """
    Return semantic classification tags for a file path.

    Normalizes backslashes to '/' and matches case-insensitively on filename and path segments.
    Supported multi-label tags:
      - docker: Dockerfile*, Containerfile*, compose*
      - compose: docker-compose*.yml/yaml, compose*.yml/yaml
      - ci: umbrella tag for all supported CI platforms
      - github-actions: .github/workflows/*.yml/yaml
      - gitlab-ci: .gitlab-ci*.yml/yaml
      - circleci: .circleci/*.yml/yaml
      - bitbucket-pipelines: bitbucket-pipelines.yml/yaml
      - azure-pipelines: azure-pipelines*.yml/yaml
      - kubernetes: path hints (k8s/, kubernetes/) or light content sniff for apiVersion + kind
      - terraform: *.tf, *.tfvars, *.hcl
      - env: *.env, .env*
      - yaml: *.yaml, *.yml
      - json: *.json
      - toml: *.toml
      - firebase: firebase.json, .firebaserc, *.rules
      - config: general configuration, environments, deployments, and manifests
      - code: source code (.py, .js, .ts, .sh, .bash, .go, .java, .php, .rb, .cs)
      - secret-file: private keys, certs, .npmrc, .pypirc, .netrc
    """
    path_obj = Path(path)
    path_str = str(path).replace("\\", "/")
    pure_posix = PurePosixPath(path_str)
    parts = [p.lower() for p in pure_posix.parts]
    filename = parts[-1] if parts else ""

    tags: Set[str] = set()

    # 1. Format tags
    is_yaml = filename.endswith(".yaml") or filename.endswith(".yml")
    if is_yaml:
        tags.add("yaml")

    if filename.endswith(".json"):
        tags.add("json")

    if filename.endswith(".toml"):
        tags.add("toml")

    # 2. Environment files
    if filename == ".env" or filename.startswith(".env.") or filename.endswith(".env"):
        tags.add("env")

    # 3. Docker & Compose
    is_compose = (
        filename.startswith("docker-compose") or filename.startswith("compose")
    ) and is_yaml
    if is_compose:
        tags.add("compose")
        tags.add("docker")

    is_dockerfile = (
        (filename == "dockerfile" or filename.startswith("dockerfile."))
        and not filename.endswith(BACKUP_EXTENSIONS)
    )
    is_containerfile = (
        (filename == "containerfile" or filename.startswith("containerfile."))
        and not filename.endswith(BACKUP_EXTENSIONS)
    )
    if is_dockerfile or is_containerfile:
        tags.add("docker")

    # 4. CI Platforms
    is_gh_actions = (
        ".github/workflows/" in path_str.lower()
        or path_str.lower().startswith(".github/workflows/")
    ) and is_yaml
    if is_gh_actions:
        tags.add("github-actions")
        tags.add("ci")

    is_gitlab = filename.startswith(".gitlab-ci") and is_yaml
    if is_gitlab:
        tags.add("gitlab-ci")
        tags.add("ci")

    is_circleci = (
        ".circleci/" in path_str.lower() or path_str.lower().startswith(".circleci/")
    ) and is_yaml
    if is_circleci:
        tags.add("circleci")
        tags.add("ci")

    is_bitbucket = filename in ("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml")
    if is_bitbucket:
        tags.add("bitbucket-pipelines")
        tags.add("ci")

    is_azure = (
        filename
        in (
            "azure-pipelines.yml",
            "azure-pipelines.yaml",
            ".azure-pipelines.yml",
            ".azure-pipelines.yaml",
        )
        or (
            ("azure-pipelines" in filename or "azure-pipeline" in filename)
            and is_yaml
        )
    )
    if is_azure:
        tags.add("azure-pipelines")
        tags.add("ci")

    # 5. Kubernetes
    has_k8s_path = any(part in ("k8s", "kubernetes") for part in parts[:-1])
    is_k8s = False
    if has_k8s_path:
        is_k8s = True
    elif is_yaml and path_obj.exists():
        is_k8s = _sniff_kubernetes(path_obj)

    if is_k8s:
        tags.add("kubernetes")

    # 6. Terraform / IaC
    if filename.endswith((".tf", ".tfvars", ".hcl")):
        tags.add("terraform")

    # 7. Firebase
    if (
        filename in ("firebase.json", ".firebaserc")
        or filename.endswith(".rules")
    ):
        tags.add("firebase")

    # 8. Secret Files
    if (
        filename in SECRET_FILE_NAMES
        or filename.endswith(SECRET_FILE_EXTENSIONS)
    ):
        tags.add("secret-file")

    # 9. Source Code
    if filename.endswith(CODE_EXTENSIONS):
        tags.add("code")

    # 10. General Config
    # If the file is structured configuration, env, compose, ci, k8s, terraform, or firebase
    if (
        "env" in tags
        or "compose" in tags
        or "ci" in tags
        or "kubernetes" in tags
        or "terraform" in tags
        or "firebase" in tags
        or is_yaml
        or "json" in tags
        or "toml" in tags
        or filename.endswith((".ini", ".conf", ".cfg"))
    ):
        tags.add("config")

    return tags


def list_files_by_type(
    root: Union[str, Path],
    types: Optional[Union[List[str], Set[str]]] = None,
    exclude: Optional[Union[List[str], Set[str], tuple, str]] = None,
) -> Dict[str, List[str]]:
    """
    Discover files in repository root using discover_files() and map each tag to sorted POSIX relative paths.

    Applies the existing ignore list, symlink rules, binary skips, and 1 MB size limit.
    If `types` is specified, returns only the requested tags in the dictionary.
    """
    root_path = Path(root)
    discovered = discover_files(root_path, exclude=exclude)

    selected_tags = set(types) if types is not None else ALL_TAGS
    result: Dict[str, List[str]] = {tag: [] for tag in sorted(selected_tags)}

    for pf in discovered:
        rel_posix = pf.path
        full_path = root_path / rel_posix if root_path.is_dir() else root_path
        file_tags = get_file_types(full_path if full_path.exists() else rel_posix)

        for tag in file_tags:
            if tag in result:
                result[tag].append(rel_posix)

    for tag in result:
        result[tag].sort()

    return result
