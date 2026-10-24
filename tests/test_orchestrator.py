import shutil
from pathlib import Path
from unittest.mock import patch
import pytest

from scanner.models import Environment, Finding, ScanResult, Severity
from scanner.orchestrator import scan_project, scan_project_result
from scanner.rules import RuleDefinition


@pytest.fixture
def sample_project(tmp_path):
    """Fixture with a sample vulnerable file matching existing regex rules."""
    proj = tmp_path / "my_project"
    proj.mkdir()
    app_file = proj / "app.py"
    app_file.write_text("DEBUG = True\n", encoding="utf-8")
    return proj


@pytest.fixture
def fake_tool_rules():
    """Fake gitleaks and semgrep rules."""
    gitleaks_rule = RuleDefinition(
        id="fake-gitleaks-rule",
        title="Fake Gitleaks Rule",
        severity=Severity.HIGH,
        message="Fake secret detected",
        recommendation="Remove secret",
        engine="gitleaks",
        pattern="",
        file_globs=["*.py"],
    )
    semgrep_rule = RuleDefinition(
        id="fake-semgrep-rule",
        title="Fake Semgrep Rule",
        severity=Severity.MEDIUM,
        message="Fake insecure code detected",
        recommendation="Fix code pattern",
        engine="semgrep",
        pattern="",
        file_globs=["*.py"],
    )
    return [gitleaks_rule, semgrep_rule]


def test_scan_project_result_no_missing_tools_gives_empty_errors(sample_project):
    """With default repo rules (all engine: regex) and available tools, errors list is empty."""
    with patch("scanner.orchestrator.is_gitleaks_available", return_value=True), \
         patch("scanner.orchestrator.is_semgrep_available", return_value=True):
        result = scan_project_result(sample_project)

    assert isinstance(result, ScanResult)
    assert result.status == "success"
    assert result.errors == []
    assert len(result.findings) >= 1
    assert result.findings[0].rule_id == "code-debug-mode"

    # scan_project is a thin wrapper returning .findings
    direct_findings = scan_project(sample_project)
    assert [f.to_dict() for f in direct_findings] == [f.to_dict() for f in result.findings]


def test_missing_tools_with_no_tool_rules_gives_empty_errors(sample_project, monkeypatch):
    """If no rules with engine: gitleaks/semgrep exist, missing tools are ignored as noise."""
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    monkeypatch.setattr("scanner.orchestrator.is_gitleaks_available", lambda: False)
    monkeypatch.setattr("scanner.orchestrator.is_semgrep_available", lambda: False)

    result = scan_project_result(sample_project)

    assert result.status == "success"
    assert result.errors == []
    assert len(result.findings) >= 1


def test_injected_tool_rules_populate_errors_when_tools_missing(sample_project, fake_tool_rules, monkeypatch):
    """
    When rules for gitleaks and semgrep are loaded, monkeypatching tool availability
    to False populates errors while leaving findings unchanged.
    """
    # 1. Base run where both tools are available: errors is empty
    with patch("scanner.orchestrator._get_loaded_rules", return_value=fake_tool_rules), \
         patch("scanner.orchestrator.is_gitleaks_available", return_value=True), \
         patch("scanner.orchestrator.is_semgrep_available", return_value=True):
        baseline_result = scan_project_result(sample_project)

    assert baseline_result.status == "success"
    assert baseline_result.errors == []
    baseline_findings = [f.to_dict() for f in baseline_result.findings]

    # 2. Only Gitleaks missing
    with patch("scanner.orchestrator._get_loaded_rules", return_value=fake_tool_rules), \
         patch("scanner.orchestrator.is_gitleaks_available", return_value=False), \
         patch("scanner.orchestrator.is_semgrep_available", return_value=True):
        gl_missing_result = scan_project_result(sample_project)

    assert gl_missing_result.status == "success"
    assert len(gl_missing_result.errors) == 1
    assert "Gitleaks is not installed" in gl_missing_result.errors[0]
    assert [f.to_dict() for f in gl_missing_result.findings] == baseline_findings

    # 3. Only Semgrep missing
    with patch("scanner.orchestrator._get_loaded_rules", return_value=fake_tool_rules), \
         patch("scanner.orchestrator.is_gitleaks_available", return_value=True), \
         patch("scanner.orchestrator.is_semgrep_available", return_value=False):
        sg_missing_result = scan_project_result(sample_project)

    assert sg_missing_result.status == "success"
    assert len(sg_missing_result.errors) == 1
    assert "Semgrep is not installed" in sg_missing_result.errors[0]
    assert [f.to_dict() for f in sg_missing_result.findings] == baseline_findings

    # 4. Both tools missing (using shutil.which monkeypatch and availability functions)
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    with patch("scanner.orchestrator._get_loaded_rules", return_value=fake_tool_rules), \
         patch("scanner.orchestrator.is_gitleaks_available", return_value=False), \
         patch("scanner.orchestrator.is_semgrep_available", return_value=False):
        both_missing_result = scan_project_result(sample_project)

    assert both_missing_result.status == "success"
    assert len(both_missing_result.errors) == 2
    assert any("Gitleaks is not installed" in e for e in both_missing_result.errors)
    assert any("Semgrep is not installed" in e for e in both_missing_result.errors)
    # Findings remain identical
    assert [f.to_dict() for f in both_missing_result.findings] == baseline_findings


def test_run_rules_unexpected_exception_gives_non_crashing_scan_result(sample_project, monkeypatch):
    """An unexpected exception during run_rules gives a non-crashing ScanResult with failure status and generic error."""
    secret_in_exception = "SUPER_SECRET_TOKEN_IN_TRACEBACK"

    def crashing_run_rules(*args, **kwargs):
        raise RuntimeError(f"Unexpected crash with secret: {secret_in_exception}")

    monkeypatch.setattr("scanner.orchestrator.run_rules", crashing_run_rules)

    result = scan_project_result(sample_project)

    assert isinstance(result, ScanResult)
    assert result.status == "failure"
    assert result.findings == []
    assert len(result.errors) == 1
    assert "An unexpected error occurred during rule execution." in result.errors[0]
    # Assert raw exception text containing secret never appears in errors
    assert secret_in_exception not in result.errors[0]


def test_single_file_and_directory_modes_go_through_same_path(tmp_path):
    """Both single-file and directory modes invoke scan_project_result identically."""
    test_file = tmp_path / "vuln.py"
    test_file.write_text("DEBUG = True\n", encoding="utf-8")

    # Single-file mode
    single_res = scan_project_result(test_file)
    assert isinstance(single_res, ScanResult)
    assert single_res.status == "success"
    assert len(single_res.findings) == 1
    assert single_res.errors == []

    # Directory mode
    dir_res = scan_project_result(tmp_path)
    assert isinstance(dir_res, ScanResult)
    assert dir_res.status == "success"
    assert len(dir_res.findings) == 1
    assert dir_res.errors == []

    # Wrapper scan_project works identically for both
    assert [f.to_dict() for f in scan_project(test_file)] == [f.to_dict() for f in single_res.findings]
    assert [f.to_dict() for f in scan_project(tmp_path)] == [f.to_dict() for f in dir_res.findings]
