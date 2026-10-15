from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    severity: str
    message: str
    environment: str
    classification_confidence: str
    recommendation: str
    source: str

@dataclass
class ScanResult:
    status: str
    findings: List[Finding]
    errors: List[str]