import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
import yaml


@dataclass
class ProjectContext:
    root: Optional[Path] = None
    deployed_files: Set[str] = field(default_factory=set)
    local_files: Set[str] = field(default_factory=set)
    production_config_globs: List[str] = field(default_factory=list)
    local_config_globs: List[str] = field(default_factory=list)
    deployed_globs: Dict[str, str] = field(default_factory=dict)
    local_globs: Dict[str, str] = field(default_factory=dict)
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
        for pat, evidence in self.deployed_globs.items():
            if fnmatch.fnmatch(norm, pat):
                return True, [evidence]

        return False, []

    def is_configured_local_only(self, file_path: str) -> Tuple[bool, List[str]]:
        norm = Path(file_path).as_posix().lstrip("./")
        if norm in self.local_files:
            return True, list(self.file_evidence.get(norm, [])) or [f"Referenced by local/test configuration: {norm}"]
        name = Path(norm).name
        for pat in self.local_config_globs:
            clean_pat = pat.lstrip("./")
            if fnmatch.fnmatch(norm, clean_pat) or fnmatch.fnmatch(name, clean_pat):
                return True, [f"Matched localOnlyFiles glob '{pat}' in scanner.config.json"]
        for pat, evidence in self.local_globs.items():
            if fnmatch.fnmatch(norm, pat):
                return True, [evidence]
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
    except Exception:
        ctx.project_evidence.append("Warning: malformed firebase.json.")


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
    except Exception:
        ctx.project_evidence.append("Warning: malformed .firebaserc.")


def _load_docker_compose(root: Path, ctx: ProjectContext) -> None:
    compose_files = sorted(
        {*root.rglob("docker-compose*.yml"), *root.rglob("docker-compose*.yaml"), *root.rglob("compose*.yml"), *root.rglob("compose*.yaml")},
        key=lambda p: p.relative_to(root).as_posix(),
    )
    for comp in compose_files:
        if not comp.is_file():
            continue
        try:
            rel_comp = comp.relative_to(root).as_posix().lstrip("./")
        except ValueError:
            rel_comp = comp.name

        try:
            content = comp.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                continue
            services = data.get("services", {})
            if not isinstance(services, dict):
                continue
            for s_name, s_conf in services.items():
                if not isinstance(s_conf, dict):
                    continue
                service_tokens = set(re.split(r"[._-]+", str(s_name).lower()))
                compose_tokens = set(re.split(r"[._-]+", comp.stem.lower()))
                profiles = s_conf.get("profiles", [])
                profile_values = profiles if isinstance(profiles, list) else [profiles]
                profile_tokens = {token for value in profile_values for token in re.split(r"[._-]+", str(value).lower())}
                env = s_conf.get("environment", {})
                env_values = list(env.values()) if isinstance(env, dict) else env if isinstance(env, list) else []
                env_tokens = {token for value in env_values for token in re.split(r"[=.:/_-]+", str(value).lower())}
                local_markers = {"local", "dev", "development", "test", "mock"}
                prod_markers = {"prod", "production"}
                service_is_local = bool((service_tokens | compose_tokens | profile_tokens | env_tokens) & local_markers)
                service_is_prod = bool((service_tokens | compose_tokens | profile_tokens | env_tokens) & prod_markers)
                if service_is_local and service_is_prod:
                    service_is_local = False
                if service_is_prod:
                    ctx.deployed_files.add(rel_comp)
                    ctx.add_file_evidence(rel_comp, f"Production Compose service '{s_name}' in {rel_comp}")
                elif service_is_local:
                    ctx.local_files.add(rel_comp)
                    ctx.add_file_evidence(rel_comp, f"Local/test Compose service '{s_name}' in {rel_comp}")
                if not (service_is_local or service_is_prod):
                    continue
                ref_set = ctx.deployed_files if service_is_prod else ctx.local_files
                ref_label = "production" if service_is_prod else "local/test"
                ref_globs = ctx.deployed_globs if service_is_prod else ctx.local_globs

                def mark_directory(path_value: str, evidence: str) -> None:
                    normalized = path_value.rstrip("/")
                    if normalized:
                        ref_globs[f"{normalized}/**"] = evidence

                # Build context / dockerfile
                build = s_conf.get("build")
                if isinstance(build, str):
                    p = (comp.parent / build).resolve()
                    try: p = p.relative_to(root).as_posix()
                    except ValueError: p = Path(build).as_posix().lstrip("./")
                    ref_set.add(p)
                    evidence = f"Build path referenced by {ref_label} service '{s_name}' in {rel_comp}"
                    ctx.add_file_evidence(p, evidence)
                    mark_directory(p, evidence)
                elif isinstance(build, dict):
                    context_path = build.get("context", ".")
                    context_abs = (comp.parent / str(context_path)).resolve()
                    try: context_rel = context_abs.relative_to(root).as_posix()
                    except ValueError: context_rel = Path(str(context_path)).as_posix().lstrip("./")
                    context_evidence = f"Build context referenced by {ref_label} service '{s_name}' in {rel_comp}"
                    if context_rel == ".":
                        ref_globs["**"] = context_evidence
                    elif context_rel:
                        ctx.add_file_evidence(context_rel, context_evidence)
                        mark_directory(context_rel, context_evidence)
                    df = build.get("dockerfile", "Dockerfile")
                    if isinstance(df, str):
                        p = (comp.parent / str(context_path) / df).resolve()
                        try: p = p.relative_to(root).as_posix()
                        except ValueError: p = Path(df).as_posix().lstrip("./")
                        ref_set.add(p)
                        ctx.add_file_evidence(p, f"Dockerfile referenced by {ref_label} service '{s_name}' in {rel_comp}")

                # env_file
                env_file = s_conf.get("env_file")
                env_list = [env_file] if isinstance(env_file, str) else (env_file if isinstance(env_file, list) else [])
                for ef in env_list:
                    if isinstance(ef, dict):
                        ef = ef.get("path")
                    if isinstance(ef, str):
                        p = (comp.parent / ef).resolve()
                        try: p = p.relative_to(root).as_posix()
                        except ValueError: p = Path(ef).as_posix().lstrip("./")
                        ref_set.add(p)
                        ctx.add_file_evidence(p, f"env_file referenced by {ref_label} service '{s_name}' in {rel_comp}")

                # volumes
                volumes = s_conf.get("volumes", [])
                if isinstance(volumes, list):
                    for v in volumes:
                        if isinstance(v, str) and ":" in v:
                            host_part = v.split(":")[0].strip()
                            if host_part.startswith(("./", "../", "/", "~")) or (len(host_part) > 2 and host_part[1:3] in (":\\", ":/")):
                                p = (comp.parent / host_part).resolve()
                                try: p = p.relative_to(root).as_posix()
                                except ValueError: p = Path(host_part).as_posix().lstrip("./")
                                ref_set.add(p)
                                ctx.add_file_evidence(p, f"Volume referenced by {ref_label} service '{s_name}' in {rel_comp}")
                                mark_directory(p, f"Volume referenced by {ref_label} service '{s_name}' in {rel_comp}")
                        elif isinstance(v, dict) and str(v.get("type", "")) == "bind" and isinstance(v.get("source"), str):
                            p = (comp.parent / v["source"]).resolve()
                            try: p = p.relative_to(root).as_posix()
                            except ValueError: p = Path(v["source"]).as_posix().lstrip("./")
                            ref_set.add(p)
                            evidence = f"Volume referenced by {ref_label} service '{s_name}' in {rel_comp}"
                            ctx.add_file_evidence(p, evidence)
                            mark_directory(p, evidence)
        except Exception:
            ctx.project_evidence.append(f"Warning: malformed Compose file {rel_comp}.")


def _load_github_workflows(root: Path, ctx: ProjectContext) -> None:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    wf_files = sorted([*wf_dir.glob("*.yml"), *wf_dir.glob("*.yaml")], key=lambda p: p.name)
    for wf in wf_files:
        if not wf.is_file():
            continue
        try:
            content = wf.read_text(encoding="utf-8")
            data = yaml.load(content, Loader=yaml.BaseLoader)
            if not isinstance(data, dict):
                continue

            jobs = data.get("jobs", {})
            deploy_job_names = set()
            if isinstance(jobs, dict):
                for job_name, job in jobs.items():
                    if not isinstance(job, dict):
                        continue
                    raw_env = job.get("environment", "")
                    if isinstance(raw_env, dict):
                        raw_env = raw_env.get("name", "")
                    env = str(raw_env).lower()
                    steps = job.get("steps", [])
                    step_text = " ".join(str(value) for value in _walk_values(steps)).lower()
                    has_deploy_command = any(
                        marker in step_text for marker in ("firebase deploy", "docker push", "kubectl apply", "terraform apply", "aws deploy", "az webapp", "deploy-pages")
                    )
                    uses_deploy_action = any(
                        marker in step_text for marker in ("action-hosting-deploy", "deploy-cloudrun", "azure/webapps-deploy", "deploy-to-aws")
                    )
                    if has_deploy_command or uses_deploy_action or env in {"production", "prod"}:
                        deploy_job_names.add(str(job_name))
            if not deploy_job_names:
                continue

            text_values = [str(v) for v in _walk_values(data)]
            referenced = set()
            known = ("firebase.json", ".firebaserc", "firestore.rules", "storage.rules", "Dockerfile", "Dockerfile.prod", "docker-compose.yml", "docker-compose.yaml")
            for value in text_values:
                for name in known:
                    if name in value:
                        referenced.add(name)
            # Resolve references against actual project files and preserve nested paths.
            for rel in sorted(referenced):
                for candidate in root.rglob(Path(rel).name):
                    try: path = candidate.relative_to(root).as_posix()
                    except ValueError: continue
                    ctx.deployed_files.add(path)
                    ctx.add_file_evidence(path, f"Referenced by deployment job in GitHub Actions workflow '{wf.name}'")
        except Exception:
            ctx.project_evidence.append(f"Warning: malformed workflow {wf.name}.")


def _walk_values(value):
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_values(child)
    elif isinstance(value, (str, int, float, bool)):
        yield value


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
    except Exception:
        ctx.project_evidence.append("Warning: malformed scanner.config.json.")


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
