import re
from pathlib import Path, PurePosixPath
from typing import List, Optional, Set, Union
from scanner.context import ProjectContext, load_project_context
from scanner.models import EnvClassification, Environment

PROD_SEGMENTS: Set[str] = {
    "prod",
    "production",
    "deploy",
    "deployment",
}

LOCAL_SEGMENTS: Set[str] = {
    "tests",
    "test",
    "fixtures",
    "fixture",
    "mocks",
    "mock",
    "examples",
    "example",
    "spec",
    "specs",
}

DEV_SEGMENTS: Set[str] = {
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
        sub_tokens = [tok.lower() for tok in re.split(r"[._\-]+", part) if tok]
        segments.extend(sub_tokens)
    return segments


def classify_environment(
    file_path: Union[str, Path],
    root: Optional[Union[str, Path]] = None,
    context: Optional[ProjectContext] = None,
) -> EnvClassification:
    """
    Classify the execution environment for a file using multiple project context signals:
    1. Conflict: declared local-only (config or path) but deployed -> production (0.95) + CONFLICT evidence.
    2. Deployed via firebase.json, deploy workflows, or scanner.config.json productionFiles -> production (0.9+).
    3. Conflicting path signals (prod + local/dev) without deployment -> unknown (0.2-0.3).
    4. Local-only via scanner.config.json or tests/fixtures/mocks/examples path segments -> local-testing (0.7-0.8).
    5. Path segments only (prod/, docker-compose.prod.yml, dev/) -> 0.5-0.6.
    6. No clear signals -> unknown (0.2-0.3).
    """
    p = Path(file_path)

    # Resolve context if not provided
    if context is None:
        if root is not None:
            context = load_project_context(root)
        else:
            # Single-file save-time scanning without explicit root
            candidate_root = None
            if p.is_absolute():
                for parent in p.parents:
                    if (
                        (parent / "firebase.json").exists()
                        or (parent / "scanner.config.json").exists()
                        or (parent / ".firebaserc").exists()
                        or (parent / ".git").exists()
                    ):
                        candidate_root = parent
                        break
            if candidate_root:
                context = load_project_context(candidate_root)
            else:
                context = ProjectContext()

    # Determine relative path key for lookup
    if context.root and p.is_absolute():
        try:
            rel_path = p.relative_to(context.root).as_posix()
        except ValueError:
            rel_path = p.as_posix()
    elif root and p.is_absolute():
        try:
            rel_path = p.relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            rel_path = p.as_posix()
    else:
        rel_path = p.as_posix()

    # Check project-level deployment signals
    is_deployed, deploy_evidence = context.is_deployed(rel_path)

    # Check project-level local-only configuration
    is_config_local, config_local_evidence = context.is_configured_local_only(rel_path)

    # Check path segments
    segments = _extract_segments(rel_path)
    path_local_matched: List[str] = []
    path_prod_matched: List[str] = []
    path_dev_matched: List[str] = []

    for seg in segments:
        if seg in LOCAL_SEGMENTS and seg not in [m.split("'")[1] for m in path_local_matched if "'" in m]:
            path_local_matched.append(f"Path segment '{seg}' indicates local-testing environment")
        if seg in PROD_SEGMENTS and seg not in [m.split("'")[1] for m in path_prod_matched if "'" in m]:
            path_prod_matched.append(f"Path segment '{seg}' indicates production environment")
        if seg in DEV_SEGMENTS and seg not in [m.split("'")[1] for m in path_dev_matched if "'" in m]:
            path_dev_matched.append(f"Path segment '{seg}' indicates local development environment")

    is_local_only = is_config_local or bool(path_local_matched)
    local_evidence = config_local_evidence or path_local_matched

    # 1. Conflict: local-only (config or path) but also deployed -> production 0.95 with CONFLICT evidence
    if is_deployed and is_local_only:
        conflict_evidence = ["CONFLICT: declared local-only but deployed to production"]
        return EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.95,
            evidence=conflict_evidence + deploy_evidence + local_evidence,
        )

    # 2. Strongest: Deployed in firebase.json / deploy job / productionFiles -> production 0.9+
    if is_deployed:
        evidence = deploy_evidence + (path_prod_matched if path_prod_matched else [])
        return EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.95,
            evidence=evidence or ["Deployed project resource"],
        )

    # 3. Conflicting path signals (prod + local/dev) without deployment -> unknown (0.2-0.3)
    if (path_prod_matched and path_local_matched) or (path_prod_matched and path_dev_matched):
        return EnvClassification(
            environment=Environment.UNKNOWN.value,
            confidence=0.25,
            evidence=["Ambiguous environment: path matches conflicting production and local-testing signals"]
            + path_prod_matched
            + (path_local_matched or path_dev_matched),
        )

    # 4. Local-only: explicit localOnlyFiles or tests/, fixtures/, mocks/, examples/ -> local-testing (0.7-0.8)
    if is_local_only:
        return EnvClassification(
            environment=Environment.LOCAL_TESTING.value,
            confidence=0.8,
            evidence=local_evidence,
        )

    # 5. Path segment signals only (prod/, docker-compose.prod.yml, dev/) -> 0.5-0.6
    if path_prod_matched:
        return EnvClassification(
            environment=Environment.PRODUCTION.value,
            confidence=0.6,
            evidence=path_prod_matched,
        )

    if path_dev_matched:
        return EnvClassification(
            environment=Environment.LOCAL_TESTING.value,
            confidence=0.6,
            evidence=path_dev_matched,
        )

    # 6. Nothing clear -> unknown (0.2-0.3)
    return EnvClassification(
        environment=Environment.UNKNOWN.value,
        confidence=0.2,
        evidence=["No environment signals detected; defaulted to unknown"],
    )


def classify_environment_tuple(
    file_path: Union[str, Path],
    root: Optional[Union[str, Path]] = None,
    context: Optional[ProjectContext] = None,
) -> tuple:
    """Thin tuple-compatibility wrapper returning (environment, confidence, evidence)."""
    ec = classify_environment(file_path, root=root, context=context)
    return (ec.environment, ec.confidence, ec.evidence)