"""Build and run the installed CLI away from the source checkout."""
from __future__ import annotations

import os
import tarfile
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="context-scanner-smoke-") as temporary:
        work = Path(temporary)
        dist = work / "dist"
        dist.mkdir()
        run([sys.executable, "-m", "pip", "wheel", str(ROOT), "--no-deps", "--no-build-isolation", "--wheel-dir", str(dist)], cwd=work)
        wheel = next(dist.glob("*.whl"))
        subprocess.run(
            [sys.executable, "-c", "from setuptools.build_meta import build_sdist; import sys; build_sdist(sys.argv[1])", str(dist)],
            cwd=ROOT,
            check=True,
        )
        required = {
            "rules/exceptions.yaml",
            "rules/insecure-code.yaml",
            "rules/insecure-config.yaml",
            "rules/secrets.yaml",
            "rules/gitleaks.toml",
            "rules/semgrep/insecure-code.yaml",
            "rules/semgrep/insecure-config.yaml",
            "schema/finding.schema.json",
        }
        with zipfile.ZipFile(wheel) as archive:
            wheel_files = {name.replace("\\", "/") for name in archive.namelist()}
        if not all(any(name.endswith(item) for name in wheel_files) for item in required):
            raise RuntimeError("Wheel is missing one or more built-in rule/schema resources.")
        source_archive = next(dist.glob("*.tar.gz"))
        with tarfile.open(source_archive, "r:gz") as archive:
            source_files = {name.split("/", 1)[-1] for name in archive.getnames()}
        if not required.issubset(source_files):
            raise RuntimeError("Source distribution is missing one or more built-in rule/schema resources.")
        venv = work / "venv"
        run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], cwd=work)
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], cwd=work)
        project = work / "outside-checkout"
        project.mkdir()
        (project / "firestore.rules").write_text("allow read, write: if true;\n", encoding="utf-8")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        result = subprocess.run(
            [str(python), "-m", "scanner", "scan", str(project)],
            cwd=project,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Installed CLI failed ({result.returncode}): {result.stderr.strip()}")
        if '"rule_id": "firebase-open-access"' not in result.stdout:
            raise RuntimeError("Installed CLI did not load its built-in rules outside the checkout.")
        print("Installed CLI smoke check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
