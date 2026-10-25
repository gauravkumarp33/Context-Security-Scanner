import datetime
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
from scanner.severity import (
    SEVERITY_ORDER,
    _lower_severity,
    _raise_severity,
    adjust_severity,
    adjust_severity_for_rule,
    get_rule_category,
)

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
    raise_in_production: bool = False
    what_it_detects: Optional[str] = None
    why_risky: Optional[str] = None
    bad_example: Optional[str] = None
    fixed_example: Optional[str] = None


@dataclass
class RawFinding:
    rule_id: str
    line: int
    message: str
    recommendation: str
    severity: Severity
    category: Optional[str] = None
    is_real_secret: bool = False
    raise_in_production: bool = False


@dataclass
class RuleException:
    file_glob: str
    rule_id: str
    reason: str
    expiry: str


def load_exceptions(yaml_path: Path) -> List[RuleException]:
    """Load security exceptions from an exceptions.yaml file."""
    exceptions: List[RuleException] = []
    path = Path(yaml_path)
    if not path.exists() or not path.is_file():
        return exceptions
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data:
            return exceptions
        items = data.get("exceptions", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            return exceptions
        for entry in items:
            if not isinstance(entry, dict):
                continue
            file_glob = str(entry.get("file_glob") or entry.get("glob") or "*").strip()
            rule_id = str(entry.get("rule_id") or "*").strip()
            reason = str(entry.get("reason") or "Exception granted").strip()
            expiry = str(entry.get("expiry") or "").strip()
            exceptions.append(
                RuleException(
                    file_glob=file_glob,
                    rule_id=rule_id,
                    reason=reason,
                    expiry=expiry,
                )
            )
    except Exception as e:
        logger.warning(f"Failed to load exceptions from {yaml_path}: {e}")
    return exceptions


def is_exception_active(exc: RuleException) -> bool:
    """Return True if exception is active (not expired)."""
    if not exc.expiry:
        return True
    try:
        expiry_date = datetime.date.fromisoformat(str(exc.expiry).strip())
        return datetime.date.today() <= expiry_date
    except Exception as e:
        logger.warning(f"Invalid expiry date '{exc.expiry}' in exception: {e}")
        return False


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
                        raise_in_production=rule.raise_in_production,
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
                    raise_in_production=rule.raise_in_production if rule else False,
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
                    raise_in_production=rule.raise_in_production if rule else False,
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

        raise_in_production = bool(item.get("raise_in_production", False))
        what_it_detects = item.get("what_it_detects") or str(item.get("title", ""))
        why_risky = item.get("why_risky") or str(item.get("message", ""))
        bad_example = item.get("bad_example")
        fixed_example = item.get("fixed_example")

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
                raise_in_production=raise_in_production,
                what_it_detects=what_it_detects,
                why_risky=why_risky,
                bad_example=bad_example,
                fixed_example=fixed_example,
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
        if yf.name == "exceptions.yaml":
            continue
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
    exceptions_file: Optional[Path] = None,
) -> List[Finding]:
    """
    Entry point for running security detection rules against files in a project.

    Args:
        project_root: Root path of the codebase.
        files: List of file paths to scan.
        classifications: Map of relative file paths to EnvClassification (or M1's raw tuple).
                         If None, missing files are classified using classify_environment with cached context.
        rules_dir: Optional path to directory containing YAML rule files.
        exceptions_file: Optional path to exceptions.yaml file.

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

    # 2. Load exceptions from configured or default locations
    loaded_exceptions: List[RuleException] = []
    if exceptions_file and Path(exceptions_file).exists():
        loaded_exceptions.extend(load_exceptions(Path(exceptions_file)))
    if rules_dir and (Path(rules_dir) / "exceptions.yaml").exists():
        loaded_exceptions.extend(load_exceptions(Path(rules_dir) / "exceptions.yaml"))
    if (project_root / "rules" / "exceptions.yaml").exists():
        loaded_exceptions.extend(load_exceptions(project_root / "rules" / "exceptions.yaml"))
    elif (DEFAULT_RULES_DIR / "exceptions.yaml").exists():
        loaded_exceptions.extend(load_exceptions(DEFAULT_RULES_DIR / "exceptions.yaml"))

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

            base_severity = rf.severity
            finding_msg = rf.message

            env_val = (
                classification.environment.value
                if isinstance(classification.environment, Environment)
                else str(classification.environment)
            ).strip().lower()

            evidence_list = classification.evidence or []
            has_conflict = any("CONFLICT" in str(ev).upper() for ev in evidence_list)

            # 1. Environment-sensitive severity
            if has_conflict:
                # If the classification evidence contains "CONFLICT", raise one level and add
                # " (declared local-only but deployed to production)" to the message.
                final_severity = _raise_severity(base_severity)
                conflict_note = " (declared local-only but deployed to production)"
                if conflict_note not in finding_msg:
                    finding_msg = f"{finding_msg}{conflict_note}"
            elif env_val == Environment.PRODUCTION.value:
                # production: keep severity; raise one level for rules marked raise_in_production: true
                # (never above critical)
                if rf.raise_in_production:
                    final_severity = _raise_severity(base_severity)
                else:
                    final_severity = base_severity
            elif env_val == Environment.LOCAL_TESTING.value:
                # local-testing: lower by at most one level, never suppress, never below low.
                # Real secrets are never lowered
                if rf.is_real_secret:
                    final_severity = base_severity
                else:
                    final_severity = _lower_severity(base_severity)
            else:
                # unknown: keep original severity, and append " (environment could not be determined)"
                # to the message.
                final_severity = base_severity
                unknown_note = " (environment could not be determined)"
                if unknown_note not in finding_msg:
                    finding_msg = f"{finding_msg}{unknown_note}"

            # 2. Exceptions handling:
            # An active exception downgrades the finding to low and adds " [exception: <reason>]" to
            # the message; it never hides it. Expired exceptions are ignored and reported as a warning.
            file_basename = Path(rel_key).name
            for exc in loaded_exceptions:
                if exc.rule_id not in ("*", rf.rule_id):
                    continue
                g = exc.file_glob
                matches = (
                    not g
                    or g == "*"
                    or fnmatch.fnmatch(rel_key, g)
                    or fnmatch.fnmatch(file_basename, g)
                    or fnmatch.fnmatch(rel_key, f"*/{g}")
                )
                if not matches:
                    continue

                if is_exception_active(exc):
                    final_severity = Severity.LOW
                    exc_note = f" [exception: {exc.reason}]"
                    if exc_note not in finding_msg:
                        finding_msg = f"{finding_msg}{exc_note}"
                    break
                else:
                    logger.warning(
                        f"Exception for rule '{exc.rule_id}' on '{exc.file_glob}' expired on {exc.expiry} and was ignored."
                    )

            findings.append(
                Finding(
                    file=rel_key,
                    line=rf.line,
                    rule_id=rf.rule_id,
                    severity=final_severity,
                    message=finding_msg,
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
