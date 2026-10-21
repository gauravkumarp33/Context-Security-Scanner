import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
import yaml


@dataclass
class ProjectContext:
    root: Optional[Path] = None
    deployed_files: Set[str] = field(default_factory=set)
    production_config_globs: List[str] = field(default_factory=list)
    local_config_globs: List[str] = field(default_factory=list)
    file_evidence: Dict[str, List[str]] = field(default_factory=dict)
    project_evidence: List[str] = field(default_factory=list)

    def add_file_evidence(self, file_path: str, evidence: str) -> None:
        norm = Path(file_path).as_posix().lstrip("./")
        self.file_evidence.setdefault(norm, []).append(evidence)

    def is_deployed(self, file_path: str) -> Tuple[bool, List[str]]:
        norm = Path(file_path).as_posix().lstrip("./")

        # Direct path match
        evidence = list(self.file_evidence.get(norm, []))
        if norm in self.deployed_files:
            return True, evidence or [f"Configured for deployment: {norm}"]

        # Config globs
        name = Path(norm).name
        for pat in self.production_config_globs:
            clean_pat = pat.lstrip("./")
            if fnmatch.fnmatch(norm, clean_pat) or fnmatch.fnmatch(name, clean_pat):
                return True, [f"Matched productionFiles glob '{pat}' in scanner.config.json"]

        return False, []

    def is_configured_local_only(self, file_path: str) -> Tuple[bool, List[str]]:
        norm = Path(file_path).as_posix().lstrip("./")
        name = Path(norm).name
        for pat in self.local_config_globs:
            clean_pat = pat.lstrip("./")
            if fnmatch.fnmatch(norm, clean_pat) or fnmatch.fnmatch(name, clean_pat):
                return True, [f"Matched localOnlyFiles glob '{pat}' in scanner.config.json"]
        return False, []


def _extract_rules_from_dict(d: Union[dict, list], ctx: ProjectContext, prefix: str = "") -> None:
    if isinstance(d, dict):
        for k, v in d.items():
            if k == "rules" and isinstance(v, str):
                norm = Path(v).as_posix().lstrip("./")
                ctx.deployed_files.add(norm)
                source_label = f" ({prefix}.rules)" if prefix else ""
                ctx.add_file_evidence(norm, f"Configured for deployment in firebase.json{source_label}")
            else:
                next_prefix = f"{prefix}.{k}" if prefix else k
                _extract_rules_from_dict(v, ctx, next_prefix)
    elif isinstance(d, list):
        for item in d:
            _extract_rules_from_dict(item, ctx, prefix)


def _load_firebase_json(root: Path, ctx: ProjectContext) -> None:
    firebase_file = root / "firebase.json"
    if not firebase_file.is_file():
        return
    try:
        content = firebase_file.read_text(encoding="utf-8")
        data = json.loads(content)
        if isinstance(data, dict):
            _extract_rules_from_dict(data, ctx)
    except Exception as e:
        ctx.project_evidence.append(f"Warning: malformed firebase.json: {e}")


def _load_firebaserc(root: Path, ctx: ProjectContext) -> None:
    rc_file = root / ".firebaserc"
    if not rc_file.is_file():
        return
    try:
        content = rc_file.read_text(encoding="utf-8")
        data = json.loads(content)
        if isinstance(data, dict):
            projects = data.get("projects", {})
            if isinstance(projects, dict):
                for alias, proj in projects.items():
                    alias_lower = str(alias).lower()
                    if alias_lower in ("prod", "production", "default"):
                        ctx.project_evidence.append(
                            f".firebaserc project alias '{alias}': '{proj}' indicates production target"
                        )
                    elif alias_lower in ("dev", "development", "staging", "test"):
                        ctx.project_evidence.append(
                            f".firebaserc project alias '{alias}': '{proj}' indicates non-production target"
                        )
    except Exception as e:
        ctx.project_evidence.append(f"Warning: malformed .firebaserc: {e}")


def _load_docker_compose(root: Path, ctx: ProjectContext) -> None:
    compose_files = list(root.glob("docker-compose*.yml")) + list(root.glob("docker-compose*.yaml"))
    for comp in compose_files:
        if not comp.is_file():
            continue
        try:
            rel_comp = comp.relative_to(root).as_posix().lstrip("./")
        except ValueError:
            rel_comp = comp.name

        is_prod_compose = "prod" in comp.name.lower()
        if is_prod_compose:
            ctx.deployed_files.add(rel_comp)
            ctx.add_file_evidence(rel_comp, f"Production docker-compose manifest: {rel_comp}")

        try:
            content = comp.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                continue
            services = data.get("services", {})
            if not isinstance(services, dict):
                continue
            for s_name, s_conf in services.items():
                is_prod_service = is_prod_compose or ("prod" in str(s_name).lower())
                if not is_prod_service or not isinstance(s_conf, dict):
                    continue

                # Build context / dockerfile
                build = s_conf.get("build")
                if isinstance(build, str):
                    p = Path(build).as_posix().lstrip("./")
                    ctx.deployed_files.add(p)
                    ctx.add_file_evidence(p, f"Build path referenced by production service '{s_name}' in {comp.name}")
                elif isinstance(build, dict):
                    df = build.get("dockerfile")
                    if isinstance(df, str):
                        p = Path(df).as_posix().lstrip("./")
                        ctx.deployed_files.add(p)
                        ctx.add_file_evidence(p, f"Dockerfile referenced by production service '{s_name}' in {comp.name}")

                # env_file
                env_file = s_conf.get("env_file")
                env_list = [env_file] if isinstance(env_file, str) else (env_file if isinstance(env_file, list) else [])
                for ef in env_list:
                    if isinstance(ef, str):
                        p = Path(ef).as_posix().lstrip("./")
                        ctx.deployed_files.add(p)
                        ctx.add_file_evidence(p, f"env_file referenced by production service '{s_name}' in {comp.name}")

                # volumes
                volumes = s_conf.get("volumes", [])
                if isinstance(volumes, list):
                    for v in volumes:
                        if isinstance(v, str) and ":" in v:
                            host_part = v.split(":")[0].strip()
                            if host_part.startswith("./") or not host_part.startswith("/"):
                                p = Path(host_part).as_posix().lstrip("./")
                                ctx.deployed_files.add(p)
                                ctx.add_file_evidence(p, f"Volume referenced by production service '{s_name}' in {comp.name}")
        except Exception as e:
            ctx.project_evidence.append(f"Warning: malformed {comp.name}: {e}")


def _load_github_workflows(root: Path, ctx: ProjectContext) -> None:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    wf_files = list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))
    for wf in wf_files:
        if not wf.is_file():
            continue
        try:
            content = wf.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                continue

            content_lower = content.lower()
            is_deploy_wf = any(
                sig in content_lower
                for sig in ("deploy", "firebase deploy", "docker push", "branches: [main", "branches: [master", "branches: [release")
            )

            if is_deploy_wf:
                matches = set()
                for m in ("firestore.rules", "storage.rules", "Dockerfile", "Dockerfile.prod"):
                    if m.lower() in content_lower:
                        matches.add(m)

                for m in matches:
                    ctx.deployed_files.add(m)
                    ctx.add_file_evidence(m, f"Referenced in deployment workflow '{wf.name}'")
        except Exception as e:
            ctx.project_evidence.append(f"Warning: malformed workflow {wf.name}: {e}")


def _load_scanner_config(root: Path, ctx: ProjectContext) -> None:
    config_file = root / "scanner.config.json"
    if not config_file.is_file():
        return
    try:
        content = config_file.read_text(encoding="utf-8")
        data = json.loads(content)
        if isinstance(data, dict):
            prod_files = data.get("productionFiles", [])
            if isinstance(prod_files, list):
                ctx.production_config_globs.extend([str(p) for p in prod_files])
            local_files = data.get("localOnlyFiles", [])
            if isinstance(local_files, list):
                ctx.local_config_globs.extend([str(l) for l in local_files])
    except Exception as e:
        ctx.project_evidence.append(f"Warning: malformed scanner.config.json: {e}")


def load_project_context(root: Union[str, Path]) -> ProjectContext:
    """
    Load project-wide context for environment classification by inspecting:
    - firebase.json
    - .firebaserc
    - docker-compose*.yml
    - .github/workflows/*.yml
    - scanner.config.json
    Handles missing or malformed files without crashing.
    """
    root_path = Path(root).resolve()
    if root_path.is_file():
        root_path = root_path.parent

    ctx = ProjectContext(root=root_path)
    if not root_path.is_dir():
        return ctx

    _load_firebase_json(root_path, ctx)
    _load_firebaserc(root_path, ctx)
    _load_docker_compose(root_path, ctx)
    _load_github_workflows(root_path, ctx)
    _load_scanner_config(root_path, ctx)

    return ctx
