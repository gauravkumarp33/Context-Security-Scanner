from scanner.analyzer import analyze_repository
from scanner.classifier import classify_environment
from scanner.models import ScanResult, Finding

def scan_project(path: str) -> ScanResult:
    files = analyze_repository(path)
    findings = []
    for file_path in files:
        env, confidence, reason = classify_environment(file_path)
    return ScanResult(status="success", findings=findings, errors=[])