from pathlib import Path
from runpy import run_path

import pytest

from scanner.rules import run_rules


plan_fixes = run_path(
    str(Path(__file__).resolve().parents[1] / "vscode-extension/python/quick_fixes.py")
)["plan_fixes"]


def test_debug_quick_fix_uses_scanner_line_and_inserts_import(tmp_path):
    source = '"""Settings."""\n\nDEBUG = True  # temporary\n'
    file = tmp_path / "settings.py"
    file.write_text(source, encoding="utf-8")
    finding = next(f for f in run_rules(tmp_path, [file]) if f.rule_id == "code-debug-mode")
    assert plan_fixes(source, [(finding.rule_id, finding.line)]) == [{
        "index": 0,
        "start": [2, 8],
        "end": [2, 12],
        "replacement": 'os.getenv("DEBUG", "False").lower() == "true"',
        "importLine": 2,
    }]


def test_debug_reuses_import_and_skips_shadowed_os():
    source = 'import os\nDEBUG = True\nHOME = os.getenv("HOME")\n'
    assert plan_fixes(source, [("code-debug-mode", 2)])[0]["importLine"] is None
    assert plan_fixes("os = object()\nDEBUG = True\n", [("code-debug-mode", 2)]) == []
    assert plan_fixes('"""\nDEBUG = True\n"""\n', [("code-debug-mode", 2)]) == []
    assert plan_fixes("DEBUG = False\n", [("code-debug-mode", 1)]) == []


def test_shell_fix_handles_unicode_editor_offsets():
    source = '"😀"; subprocess.run(["git", "status"], shell=True)\n'
    fix, = plan_fixes(source, [("code-subprocess-shell", 1)])
    expected_start = len(source[:source.index("True")].encode("utf-16-le")) // 2
    assert fix["start"] == [0, expected_start]
    assert fix["end"] == [0, expected_start + 4]
    assert fix["replacement"] == "False"


@pytest.mark.parametrize("command", ['cmd', '"git status"', '["git", "$HOME"]', '["echo", "x | cat"]'])
def test_shell_fix_skips_commands_that_may_depend_on_the_shell(command):
    source = f"subprocess.run({command}, shell=True)\n"
    assert plan_fixes(source, [("code-subprocess-shell", 1)]) == []
