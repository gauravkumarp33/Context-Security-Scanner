import logging
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union

from scanner.analyzer import classify_project, discover_files
from scanner.classifier import classify_environment
from scanner.context import load_project_context
from scanner.models import Finding, ScanResult
from scanner.rules import (
    DEFAULT_RULES_DIR,
    RuleDefinition,
    load_all_rules,
    run_rules,
)

logger = logging.getLogger(__name__)


def is_gitleaks_available() -> bool:
    """Check if Gitleaks is installed and available."""
    from scanner import rules as rules_mod
    return rules_mod.is_gitleaks_available()


def is_semgrep_available() -> bool:
    """Check if Semgrep is installed and available."""
    from scanner import rules as rules_mod
    return rules_mod.is_semgrep_available()


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


def _get_loaded_rules(project_root: Path, rules_dir: Optional[Path] = None) -> List[RuleDefinition]:
    """Resolve all active rule definitions from configured and project rule paths."""
    all_rules: List[RuleDefinition] = []
    seen_rule_ids: Set[str] = set()

    def _add_rules_from_dir(d: Path):
        from scanner import rules as rules_mod
        for r in rules_mod.load_all_rules(d):
            if r.id not in seen_rule_ids:
                all_rules.append(r)
                seen_rule_ids.add(r.id)

    if rules_dir and Path(rules_dir).exists():
        _add_rules_from_dir(Path(rules_dir))
    if (project_root / "rules").exists() and (project_root / "rules").is_dir():
        _add_rules_from_dir(project_root / "rules")
    if DEFAULT_RULES_DIR.exists() and DEFAULT_RULES_DIR.is_dir():
        _add_rules_from_dir(DEFAULT_RULES_DIR)

    return all_rules


def scan_project_result(
    root: Union[str, Path],
    exclude: Optional[Union[List[str], Set[str], Tuple[str, ...], str]] = None,
) -> ScanResult:
    """
    Scan a repository root path or a single file by classifying file environments and running security rules.
    Returns a ScanResult object containing status, findings, and errors.
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
        files = [target]
    else:
        project_root = target
        project_files = discover_files(target, exclude=exclude)
        classifications = classify_project(target, exclude=exclude)
        files = [target / pf.path for pf in project_files]

    errors: List[str] = []

    # 1. Tool availability checks: only append if rules requiring that tool engine exist
    loaded_rules = _get_loaded_rules(project_root)
    has_gitleaks_rules = any(r.engine == "gitleaks" for r in loaded_rules)
    has_semgrep_rules = any(r.engine == "semgrep" for r in loaded_rules)

    if not is_gitleaks_available() and has_gitleaks_rules:
        errors.append("Gitleaks is not installed; skipping Gitleaks engine.")

    if not is_semgrep_available() and has_semgrep_rules:
        errors.append("Semgrep is not installed; skipping Semgrep engine.")

    # 2. Run rules wrapped against unexpected exceptions
    findings: List[Finding] = []
    status = "success"

    try:
        findings = run_rules(project_root=project_root, files=files, classifications=classifications)
    except Exception as e:
        status = "failure"
        errors.append("An unexpected error occurred during rule execution.")
        logger.warning(f"Unexpected error in run_rules: {type(e).__name__}")

    return ScanResult(status=status, findings=findings, errors=errors)


def scan_project(
    root: Union[str, Path],
    exclude: Optional[Union[List[str], Set[str], Tuple[str, ...], str]] = None,
) -> List[Finding]:
    """
    Scan a repository root path or a single file by classifying file environments and running security rules.
    Returns a list of Finding objects conforming to the contract.
    """
    result = scan_project_result(root, exclude=exclude)
    return result.findings
