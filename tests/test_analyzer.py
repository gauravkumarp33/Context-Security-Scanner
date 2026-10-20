import os
import pytest
from scanner.analyzer import analyze_repository, classify_project
from scanner.models import EnvClassification


def test_analyze_repository_includes_valid_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").touch()
    (tmp_path / "README.md").touch()

    files = analyze_repository(str(tmp_path))
    normalized_files = [f.replace("\\", "/") for f in files]

    assert "src/main.py" in normalized_files
    assert "README.md" in normalized_files


def test_analyze_repository_excludes_ignored_directories(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").touch()
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "pyvenv.cfg").touch()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").touch()

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "server.py").touch()

    files = analyze_repository(str(tmp_path))
    normalized_files = [f.replace("\\", "/") for f in files]

    assert "app/server.py" in normalized_files
    assert not any(f.startswith(".git") for f in normalized_files)
    assert not any(f.startswith("venv") for f in normalized_files)
    assert not any(f.startswith("node_modules") for f in normalized_files)


def test_classify_project_posix_keys_and_exclusions(tmp_path):
    """Verify classify_project returns POSIX relative keys, correct classifications, and excludes directories."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").touch()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").touch()
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "prod_config.yaml").touch()

    # Ignored directories
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").touch()
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "pyvenv.cfg").touch()
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyvenv.cfg").touch()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.json").touch()
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "app.exe").touch()
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").touch()

    classifications = classify_project(tmp_path)

    expected_keys = {"src/main.py", "tests/test_app.py", "deploy/prod_config.yaml"}
    assert set(classifications.keys()) == expected_keys

    # Ensure POSIX format (no Windows backslashes)
    for k in classifications.keys():
        assert "\\" not in k

    # Ensure classification values
    assert isinstance(classifications["src/main.py"], EnvClassification)
    assert classifications["tests/test_app.py"].environment == "local-testing"
    assert classifications["deploy/prod_config.yaml"].environment == "production"

    # Ensure exclusions
    for ignored in [".git", "venv", ".venv", "node_modules", "build", "dist"]:
        assert not any(k.startswith(ignored) for k in classifications.keys())