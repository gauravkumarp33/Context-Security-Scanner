import fnmatch
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
import yaml

from scanner.classifier import classify_environment
from scanner.context import ProjectContext, load_project_context
from scanner.integrations.gitleaks_runner import is_gitleaks_available, run_gitleaks
from scanner.integrations.semgrep_runner import is_semgrep_available, run_semgrep
from scanner.models import EnvClassification, Environment, Finding, Severity
from scanner.severity import adjust_severity, adjust_severity_for_rule, get_rule_category

logger = logging.getLogger(__name__)

# Preserve legacy constants for backwards compatibility
FIREBASE_OPEN_ACCESS_PATTERN = re.compile(
    r"allow\s+(?:read\s*,\s*write|write\s*,\s*read)\s*:\s*if\s+true\s*;"
)
FIREBASE_OPEN_ACCESS_BASE_SEVERITY = Severity.HIGH

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

PLACEHOLDER_SUBSTRINGS: Set[str] = {
    "changeme",
    "example",
    "<your_key>",
    "<your-key>",
    "<your_secret>",
    "<your-secret>",
    "<your_token>",
    "<your-token>",
    "<your_password>",
    "<your-password>",
    "xxx",
    "placeholder",
}


def is_placeholder(val: str) -> bool:
    """Check if a matched secret value is an obvious placeholder or dummy string."""
    if not val or not val.strip():
        return True
    cleaned = val.strip().lower()
    for ph in PLACEHOLDER_SUBSTRINGS:
        if ph in cleaned:
            return True
    return False


class RuleValidationError(ValueError):
    """Raised when a rule definition fails schema or semantic validation."""
    pass


@dataclass
class RuleDefinition:
    id: str
    title: str
    severity: Severity
    message: str
    recommendation: str
    engine: str
    pattern: str
    file_globs: List[str]
    category: Optional[str] = None


@dataclass
class RawFinding:
    rule_id: str
    line: int
    message: str
    recommendation: str
    severity: Severity
    category: Optional[str] = None
    is_real_secret: bool = False


class Detector:
    """Abstract base class for security detection engines."""

    def detect(self, file_path: Path, content: str) -> List[RawFinding]:
        raise NotImplementedError


class RegexDetector(Detector):
    """Detector executing regular expression patterns against file contents."""

    def __init__(self, rules: List[RuleDefinition]):
        self.rules = rules
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        for r in rules:
            try:
                self._compiled_patterns[r.id] = re.compile(r.pattern, re.MULTILINE)
            except re.error as e:
                logger.warning(f"Failed to compile regex for rule '{r.id}': {e}")

    def detect(self, file_path: Path, content: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        rel_posix = file_path.as_posix()
        file_name = file_path.name

        for rule in self.rules:
            if rule.engine != "regex":
                continue

            # Check globs
            if not self._matches_globs(rel_posix, file_name, rule.file_globs):
                continue

            pattern = self._compiled_patterns.get(rule.id)
            if not pattern:
                continue

            for match in pattern.finditer(content):
                # Check for secret value placeholder filtering
                is_secret_rule = (
                    rule.id.startswith("secret-")
                    or "password" in rule.id
                    or "secret" in rule.id
                    or rule.category == "exposed_secret"
                )
                if is_secret_rule:
                    # Check groups or the whole matched string
                    matched_val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    if is_placeholder(matched_val):
                        continue

                # 1-based line number
                line_num = content[: match.start()].count("\n") + 1

                # Message MUST NEVER contain the secret value: name the type only
                findings.append(
                    RawFinding(
                        rule_id=rule.id,
                        line=line_num,
                        message=rule.message,
                        recommendation=rule.recommendation,
                        severity=rule.severity,
                        category=rule.category or get_rule_category(rule.id),
                        is_real_secret=is_secret_rule,
                    )
                )

        return findings

    @staticmethod
    def _matches_globs(rel_posix: str, file_name: str, globs: List[str]) -> bool:
        if not globs or "*" in globs:
            return True
        for g in globs:
            if (
                fnmatch.fnmatch(rel_posix, g)
                or fnmatch.fnmatch(file_name, g)
                or fnmatch.fnmatch(rel_posix, f"*/{g}")
            ):
                return True
        return False


def _safe_int_line(val: Any, default: int = 1) -> int:
    """Safely convert a value to a 1-based positive integer line number."""
    try:
        line = int(val)
        return max(1, line)
    except (ValueError, TypeError, OverflowError):
        return max(1, default)


class GitleaksDetector(Detector):
    """Detector wrapping the Gitleaks runner."""

    def __init__(self, rules: List[RuleDefinition], config_path: Optional[Path] = None):
        self.rules = {r.id: r for r in rules if r.engine == "gitleaks"}
        self.config_path = config_path

    def detect(self, file_path: Path, content: str) -> List[RawFinding]:
        if not self.rules:
            return []
        if not is_gitleaks_available():
            logger.warning("Gitleaks is not installed; skipping Gitleaks engine.")
            return []

        findings: List[RawFinding] = []
        raw_results = run_gitleaks(file_path, config_path=self.config_path)
        for res in raw_results:
            if not isinstance(res, dict):
                continue
            rule_id = res.get("RuleID", "gitleaks-secret")
            rule = self.rules.get(rule_id)
            line = _safe_int_line(res.get("StartLine", 1))

            message = rule.message if rule else "Hardcoded secret detected by Gitleaks."
            recommendation = (
                rule.recommendation
                if rule
                else "Remove hardcoded secret and load dynamically from secure secrets storage."
            )
            severity = rule.severity if rule else Severity.HIGH

            findings.append(
                RawFinding(
                    rule_id=rule_id,
                    line=line,
                    message=message,
                    recommendation=recommendation,
                    severity=severity,
                    category="exposed_secret",
                    is_real_secret=True,
                )
            )

        return findings


class SemgrepDetector(Detector):
    """Detector wrapping the Semgrep runner."""

    def __init__(self, rules: List[RuleDefinition], config_path: Optional[Path] = None):
        self.rules = {r.id: r for r in rules if r.engine == "semgrep"}
        self.config_path = config_path

    def detect(self, file_path: Path, content: str) -> List[RawFinding]:
        if not self.rules:
            return []
        if not is_semgrep_available():
            logger.warning("Semgrep is not installed; skipping Semgrep engine.")
            return []

        findings: List[RawFinding] = []
        raw_results = run_semgrep(file_path, config_path=self.config_path)
        for res in raw_results:
            if not isinstance(res, dict):
                continue
            rule_id = res.get("check_id", "semgrep-finding")
            rule = self.rules.get(rule_id)
            start_val = res.get("start")
            start_line = start_val.get("line", 1) if isinstance(start_val, dict) else 1
            line = _safe_int_line(start_line)

            message = rule.message if rule else "Semgrep security issue."
            recommendation = (
                rule.recommendation
                if rule
                else "Review and remediate the flagged insecure code pattern."
            )
            severity = rule.severity if rule else Severity.MEDIUM

            findings.append(
                RawFinding(
                    rule_id=rule_id,
                    line=line,
                    message=message,
                    recommendation=recommendation,
                    severity=severity,
                    category=rule.category if rule else get_rule_category(rule_id),
                    is_real_secret=False,
                )
            )

        return findings


def load_rules_from_yaml(yaml_path: Path) -> List[RuleDefinition]:
    """
    Load and validate rule definitions from a YAML file.
    Gives clear RuleValidationError on invalid format or missing required fields.
    """
    path = Path(yaml_path)
    if not path.exists():
        raise RuleValidationError(f"Rule file does not exist: {yaml_path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuleValidationError(f"Failed to parse YAML file {yaml_path}: {e}")

    if data is None:
        return []

    raw_rules: List[Dict[str, Any]]
    if isinstance(data, list):
        raw_rules = data
    elif isinstance(data, dict):
        if "rules" in data and isinstance(data["rules"], list):
            raw_rules = data["rules"]
        else:
            raw_rules = [data]
    else:
        raise RuleValidationError(f"Rule file {yaml_path} must contain a list or mapping of rules.")

    rules: List[RuleDefinition] = []
    required_fields = ["id", "title", "severity", "message", "recommendation", "engine", "pattern", "file_globs"]

    for idx, item in enumerate(raw_rules):
        if not isinstance(item, dict):
            raise RuleValidationError(f"Rule at index {idx} in {yaml_path} must be a dictionary.")

        for req in required_fields:
            if req not in item or item[req] is None:
                raise RuleValidationError(
                    f"Rule at index {idx} in {yaml_path} missing required field '{req}'."
                )

        # Validate severity
        raw_sev = str(item["severity"]).strip().lower()
        try:
            severity = Severity(raw_sev)
        except ValueError:
            raise RuleValidationError(
                f"Invalid severity '{item['severity']}' in rule '{item['id']}'. Must be low, medium, high, or critical."
            )

        # Validate engine
        raw_engine = str(item["engine"]).strip().lower()
        if raw_engine not in {"regex", "semgrep", "gitleaks"}:
            raise RuleValidationError(
                f"Invalid engine '{item['engine']}' in rule '{item['id']}'. Must be regex, semgrep, or gitleaks."
            )

        # Validate file_globs
        file_globs = item["file_globs"]
        if isinstance(file_globs, str):
            file_globs = [file_globs]
        elif not isinstance(file_globs, list):
            raise RuleValidationError(
                f"Invalid file_globs in rule '{item['id']}': expected list of glob strings."
            )

        rules.append(
            RuleDefinition(
                id=str(item["id"]).strip(),
                title=str(item["title"]).strip(),
                severity=severity,
                message=str(item["message"]).strip(),
                recommendation=str(item["recommendation"]).strip(),
                engine=raw_engine,
                pattern=str(item["pattern"]),
                file_globs=[str(g) for g in file_globs],
                category=item.get("category"),
            )
        )

    return rules


def load_all_rules(rules_dir: Path) -> List[RuleDefinition]:
    """Load and validate all YAML rule definitions from a directory recursively."""
    all_rules: List[RuleDefinition] = []
    rules_path = Path(rules_dir)
    if not rules_path.exists() or not rules_path.is_dir():
        return all_rules

    yaml_files = sorted(list(rules_path.glob("*.yaml")) + list(rules_path.glob("*.yml")))
    for yf in yaml_files:
        try:
            rules = load_rules_from_yaml(yf)
            all_rules.extend(rules)
        except RuleValidationError as e:
            logger.warning(f"Skipping invalid rule file {yf}: {e}")

    return all_rules


def run_rules(
    project_root: Path,
    files: List[Path],
    classifications: Optional[Dict[str, Union[EnvClassification, tuple]]] = None,
    rules_dir: Optional[Path] = None,
) -> List[Finding]:
    """
    Entry point for running security detection rules against files in a project.

    Args:
        project_root: Root path of the codebase.
        files: List of file paths to scan.
        classifications: Map of relative file paths to EnvClassification (or M1's raw tuple).
                         If None, missing files are classified using classify_environment with cached context.
        rules_dir: Optional path to directory containing YAML rule files.

    Returns:
        List of Finding objects conforming to the contract.
    """
    project_root = Path(project_root).resolve()
    normalized_classifications: Dict[str, EnvClassification] = {}

    if classifications is not None:
        for path_str, raw_val in classifications.items():
            norm_key = Path(path_str).as_posix()
            if isinstance(raw_val, EnvClassification):
                normalized_classifications[norm_key] = raw_val
            elif isinstance(raw_val, (tuple, list)):
                normalized_classifications[norm_key] = EnvClassification.from_tuple(tuple(raw_val))
            elif isinstance(raw_val, dict):
                normalized_classifications[norm_key] = EnvClassification(**raw_val)
            else:
                normalized_classifications[norm_key] = EnvClassification(
                    environment=Environment.UNKNOWN.value,
                    confidence=0.0,
                    evidence=[],
                )

    # 1. Load rules from configured or default locations
    all_rules: List[RuleDefinition] = []
    seen_rule_ids: Set[str] = set()

    def _add_rules_from_dir(d: Path):
        for r in load_all_rules(d):
            if r.id not in seen_rule_ids:
                all_rules.append(r)
                seen_rule_ids.add(r.id)

    if rules_dir and Path(rules_dir).exists():
        _add_rules_from_dir(Path(rules_dir))
    if (project_root / "rules").exists() and (project_root / "rules").is_dir():
        _add_rules_from_dir(project_root / "rules")
    if DEFAULT_RULES_DIR.exists() and DEFAULT_RULES_DIR.is_dir():
        _add_rules_from_dir(DEFAULT_RULES_DIR)

    # Instantiate detectors
    regex_detector = RegexDetector(all_rules)
    gitleaks_detector = GitleaksDetector(all_rules)
    semgrep_detector = SemgrepDetector(all_rules)
    detectors: List[Detector] = [regex_detector, gitleaks_detector, semgrep_detector]

    findings: List[Finding] = []
    seen_dedupe: Set[tuple] = set()
    ctx: Optional[ProjectContext] = None
    classification_cache: Dict[str, EnvClassification] = {}

    for file_item in files:
        file_path = Path(file_item)
        if file_path.is_absolute():
            try:
                rel_key = file_path.relative_to(project_root).as_posix()
            except ValueError:
                rel_key = file_path.as_posix()
            full_path = file_path
        else:
            rel_key = file_path.as_posix()
            full_path = project_root / file_path

        if not full_path.is_file():
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Resolve classification
        if classifications is not None:
            classification = normalized_classifications.get(
                rel_key,
                EnvClassification(
                    environment=Environment.UNKNOWN.value,
                    confidence=0.0,
                    evidence=["Missing classification; defaulted to unknown"],
                ),
            )
        else:
            if rel_key in classification_cache:
                classification = classification_cache[rel_key]
            else:
                try:
                    if ctx is None:
                        ctx = load_project_context(project_root)
                    resolved_target = full_path.resolve() if full_path.exists() else full_path
                    classification = classify_environment(
                        resolved_target,
                        root=project_root,
                        context=ctx,
                    )
                    if not isinstance(classification, EnvClassification):
                        classification = EnvClassification(
                            environment=Environment.UNKNOWN.value,
                            confidence=0.0,
                            evidence=["classifier_error"],
                        )
                except Exception:
                    classification = EnvClassification(
                        environment=Environment.UNKNOWN.value,
                        confidence=0.0,
                        evidence=["classifier_error"],
                    )
                classification_cache[rel_key] = classification

        # Dispatch detectors
        raw_findings: List[RawFinding] = []
        for det in detectors:
            try:
                raw_findings.extend(det.detect(full_path, content))
            except Exception as e:
                logger.warning(f"Detector {det.__class__.__name__} failed on {full_path}: {e}")

        for rf in raw_findings:
            dedupe_key = (rf.rule_id, rel_key, rf.line)
            if dedupe_key in seen_dedupe:
                continue
            seen_dedupe.add(dedupe_key)

            final_severity = adjust_severity_for_rule(
                severity=rf.severity,
                rule_id=rf.rule_id,
                environment=classification.environment,
                confidence=classification.confidence,
                is_real_secret=rf.is_real_secret,
            )

            findings.append(
                Finding(
                    file=rel_key,
                    line=rf.line,
                    rule_id=rf.rule_id,
                    severity=final_severity,
                    message=rf.message,
                    environment=classification.environment,
                    confidence=classification.confidence,
                    recommendation=rf.recommendation,
                )
            )

    # Sort by severity (critical > high > medium > low), then file, then line
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    findings.sort(
        key=lambda item: (
            severity_order.get(
                item.severity if isinstance(item.severity, Severity) else Severity(str(item.severity).lower()),
                99,
            ),
            item.file,
            item.line,
            item.rule_id,
        )
    )

    return findings
