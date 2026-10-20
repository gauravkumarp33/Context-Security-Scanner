from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Union


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(str, Enum):
    PRODUCTION = "production"
    LOCAL_TESTING = "local-testing"
    UNKNOWN = "unknown"


@dataclass
class EnvClassification:
    environment: str = Environment.UNKNOWN.value
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    @classmethod
    def from_tuple(cls, t: tuple) -> "EnvClassification":
        env_map = {
            "test": Environment.LOCAL_TESTING.value,
            "development": Environment.LOCAL_TESTING.value,
            "dev": Environment.LOCAL_TESTING.value,
            "local": Environment.LOCAL_TESTING.value,
            "local-testing": Environment.LOCAL_TESTING.value,
            "production": Environment.PRODUCTION.value,
            "prod": Environment.PRODUCTION.value,
            "unknown": Environment.UNKNOWN.value,
        }
        conf_map = {
            "high": 0.9,
            "medium": 0.5,
            "low": 0.2,
        }
        raw_env = t[0] if len(t) > 0 else Environment.UNKNOWN.value
        norm_env = env_map.get(str(raw_env).strip().lower(), Environment.UNKNOWN.value)

        raw_conf = t[1] if len(t) > 1 else 0.0
        if isinstance(raw_conf, str):
            norm_conf = conf_map.get(raw_conf.strip().lower(), 0.0)
        else:
            try:
                norm_conf = float(raw_conf)
            except (ValueError, TypeError):
                norm_conf = 0.0

        raw_evidence = t[2] if len(t) > 2 else []
        if isinstance(raw_evidence, str):
            evidence = [raw_evidence] if raw_evidence else []
        elif isinstance(raw_evidence, (list, tuple)):
            evidence = [str(item) for item in raw_evidence]
        else:
            evidence = []

        return cls(environment=norm_env, confidence=norm_conf, evidence=evidence)

    def __post_init__(self):
        if isinstance(self.environment, Environment):
            self.environment = self.environment.value
        elif isinstance(self.environment, str):
            val = self.environment.strip().lower()
            if val in {e.value for e in Environment}:
                self.environment = val
            else:
                raise ValueError(
                    f"Invalid environment '{self.environment}'. Must be one of {[e.value for e in Environment]}"
                )
        else:
            raise ValueError(f"Invalid environment type '{type(self.environment)}'. Must be str or Environment enum.")

        if isinstance(self.confidence, str):
            conf_str = self.confidence.strip().lower()
            mapping = {"high": 0.9, "medium": 0.5, "low": 0.2}
            if conf_str in mapping:
                self.confidence = mapping[conf_str]
            else:
                try:
                    self.confidence = float(conf_str)
                except (ValueError, TypeError):
                    raise ValueError(f"Confidence must be between 0.0 and 1.0, got: {self.confidence}")
        elif not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise ValueError(f"Confidence must be a float between 0.0 and 1.0, got {type(self.confidence).__name__}")
        else:
            self.confidence = float(self.confidence)

        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got: {self.confidence}")

        if isinstance(self.evidence, str):
            self.evidence = [self.evidence]
        elif not isinstance(self.evidence, list):
            self.evidence = list(self.evidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "environment": self.environment,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }

    def __iter__(self):
        return iter((self.environment, self.confidence, self.evidence))

    def __getitem__(self, idx):
        return (self.environment, self.confidence, self.evidence)[idx]


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    severity: Union[Severity, str]
    message: str
    environment: Union[Environment, str]
    confidence: float
    recommendation: str

    def __post_init__(self):
        # Validate and normalize severity
        if isinstance(self.severity, Severity):
            pass
        elif isinstance(self.severity, str):
            val = self.severity.strip().lower()
            if val in {s.value for s in Severity}:
                object.__setattr__(self, "severity", Severity(val))
            else:
                raise ValueError(
                    f"Invalid severity '{self.severity}'. Must be one of {[s.value for s in Severity]}"
                )
        else:
            raise ValueError(f"Invalid severity type '{type(self.severity)}'. Must be str or Severity enum.")

        # Validate line
        if not isinstance(self.line, int) or isinstance(self.line, bool):
            raise ValueError(f"Line must be an integer >= 1, got {type(self.line).__name__}: {self.line}")
        if self.line < 1:
            raise ValueError(f"Line must be >= 1, got: {self.line}")

        # Validate confidence
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise ValueError(f"Confidence must be a float between 0.0 and 1.0, got {type(self.confidence).__name__}")
        conf_float = float(self.confidence)
        if not (0.0 <= conf_float <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got: {self.confidence}")
        object.__setattr__(self, "confidence", conf_float)

        # Validate and normalize environment
        if isinstance(self.environment, Environment):
            pass
        elif isinstance(self.environment, str):
            val = self.environment.strip().lower()
            if val in {e.value for e in Environment}:
                object.__setattr__(self, "environment", Environment(val))
            else:
                raise ValueError(
                    f"Invalid environment '{self.environment}'. Must be one of {[e.value for e in Environment]}"
                )
        else:
            raise ValueError(f"Invalid environment type '{type(self.environment)}'. Must be str or Environment enum.")

        # Validate string types
        if not isinstance(self.file, str):
            raise ValueError("file must be a string")
        if not isinstance(self.rule_id, str):
            raise ValueError("rule_id must be a string")
        if not isinstance(self.message, str):
            raise ValueError("message must be a string")
        if not isinstance(self.recommendation, str):
            raise ValueError("recommendation must be a string")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "message": self.message,
            "environment": self.environment.value if isinstance(self.environment, Environment) else str(self.environment),
            "confidence": self.confidence,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    status: str
    findings: List[Finding]
    errors: List[str]