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
    If Gitleaks is not installed, logs a warning and returns an empty list without crashing.
    """
    if not is_gitleaks_available():
        logger.warning("Gitleaks binary not found in PATH; skipping Gitleaks detector.")
        return []

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
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = proc.stdout.strip()
        if output:
            try:
                parsed = json.loads(output)
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                logger.warning("Failed to parse Gitleaks JSON output.")
                return []
        return []
    except Exception as e:
        logger.warning(f"Error executing Gitleaks: {e}")
        return []
