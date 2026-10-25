import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def is_gitleaks_available() -> bool:
    """Check if the gitleaks executable is available in the current environment."""
    return shutil.which("gitleaks") is not None


def run_gitleaks(
    target_path: Path, config_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """
    Run Gitleaks on the specified target path and return raw finding objects.
    Raises a sanitized RuntimeError when execution fails; callers must not report a
    partial external-tool scan as clean.
    """
    if not is_gitleaks_available():
        raise RuntimeError("Gitleaks is not installed.")

    target = Path(target_path).resolve()
    cmd = [
        "gitleaks",
        "detect",
        "--no-git",
        "--source",
        str(target),
        "--report-format",
        "json",
    ]
    if config_path and Path(config_path).exists():
        cmd.extend(["--config", str(config_path)])

    try:
        cwd = target if target.is_dir() else target.parent
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=cwd)
        if proc.returncode == 1 and not proc.stdout.strip():
            raise RuntimeError("Gitleaks reported findings without a JSON report; scan is incomplete.")
        if proc.returncode == 0 and not proc.stdout.strip():
            raise RuntimeError("Gitleaks returned no JSON output; scan is incomplete.")
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise RuntimeError("Gitleaks returned invalid JSON; scan is incomplete.") from None
        if proc.returncode not in (0, 1):
            raise RuntimeError("Gitleaks exited with an error; scan is incomplete.")
        if not isinstance(parsed, list):
            raise RuntimeError("Gitleaks returned an unexpected result shape; scan is incomplete.")
        return parsed
    except RuntimeError:
        raise
    except Exception:
        raise RuntimeError("Gitleaks could not be executed; scan is incomplete.") from None
