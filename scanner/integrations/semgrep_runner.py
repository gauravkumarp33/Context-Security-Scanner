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
    If Semgrep is not installed, logs a warning and returns an empty list without crashing.
    """
    if not is_semgrep_available():
        logger.warning("Semgrep binary not found in PATH; skipping Semgrep detector.")
        return []

    target = Path(target_path).resolve()
    cmd = ["semgrep", "scan", "--json"]
    if config_path and Path(config_path).exists():
        cmd.extend(["--config", str(config_path)])
    cmd.append(str(target))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = proc.stdout.strip()
        if output:
            try:
                parsed = json.loads(output)
                if isinstance(parsed, dict):
                    return parsed.get("results", [])
                elif isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                logger.warning("Failed to parse Semgrep JSON output.")
                return []
        return []
    except Exception as e:
        logger.warning(f"Error executing Semgrep: {e}")
        return []
