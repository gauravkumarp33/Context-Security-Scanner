import os
import pytest
from scanner.analyzer import analyze_repository

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