import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def is_semgrep_available() -> bool:
    """Check if the semgrep executable is available in the current environment."""
    return shutil.which("semgrep") is not None


def run_semgrep(
    target_path: Path, config_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """
    Run Semgrep on the specified target path and return raw result dictionaries.
    Raises a sanitized RuntimeError when execution fails; callers must not report a
    partial external-tool scan as clean.
    """
    if not is_semgrep_available():
        raise RuntimeError("Semgrep is not installed.")

    target = Path(target_path).resolve()
    cmd = ["semgrep", "scan", "--json"]
    if config_path and Path(config_path).exists():
        cmd.extend(["--config", str(config_path)])
    cmd.append(str(target))

    try:
        cwd = target if target.is_dir() else target.parent
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=cwd)
        if not proc.stdout.strip():
            raise RuntimeError("Semgrep returned no JSON output; scan is incomplete.")
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise RuntimeError("Semgrep returned invalid JSON; scan is incomplete.") from None
        if proc.returncode != 0:
            raise RuntimeError("Semgrep exited with an error; scan is incomplete.")
        results = parsed.get("results", []) if isinstance(parsed, dict) else parsed
        if not isinstance(results, list):
            raise RuntimeError("Semgrep returned an unexpected result shape; scan is incomplete.")
        return results
    except RuntimeError:
        raise
    except Exception:
        raise RuntimeError("Semgrep could not be executed; scan is incomplete.") from None
