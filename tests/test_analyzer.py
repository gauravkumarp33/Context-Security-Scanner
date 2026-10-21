import os
from unittest.mock import patch
import pytest
from scanner.analyzer import (
    analyze_repository,
    classify_project,
    determine_kind,
    discover_files,
)
from scanner.models import EnvClassification, ProjectFile


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


def test_discover_files_excluded_dirs_skipped(tmp_path):
    """Verify default excluded dirs (.git, .venv, venv, env, node_modules, __pycache__, dist, build, .idea, .vscode) and user excludes are skipped."""
    for d in [
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".idea",
        ".vscode",
    ]:
        dir_path = tmp_path / d
        dir_path.mkdir(parents=True, exist_ok=True)
        (dir_path / "ignored.py").write_text("print('skip')", encoding="utf-8")

    # User-specified exclusions
    custom_dir = tmp_path / "custom_temp"
    custom_dir.mkdir()
    (custom_dir / "skip_me.py").write_text("print('skip')", encoding="utf-8")
    (tmp_path / "backup.bak").write_text("backup data", encoding="utf-8")

    # Valid files
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log('ok')", encoding="utf-8")

    files = discover_files(tmp_path, exclude=["custom_temp", "*.bak"])
    paths = [f.path for f in files]

    assert paths == ["app.js", "src/index.py"]


def test_discover_files_binary_and_oversized_skipped(tmp_path):
    """Verify binary files (null byte in first 1 KB) and files > 1 MB are skipped."""
    # Text file
    text_file = tmp_path / "text.txt"
    text_file.write_text("Hello readable world!", encoding="utf-8")

    # Binary file
    bin_file = tmp_path / "binary.bin"
    bin_file.write_bytes(b"Header\x00BinaryContent")

    # Large file (> 1 MB)
    large_file = tmp_path / "large.txt"
    large_file.write_bytes(b"X" * (1024 * 1024 + 10))

    files = discover_files(tmp_path)
    paths = [f.path for f in files]

    assert paths == ["text.txt"]
    assert files[0].kind == "other"
    assert files[0].size == len(b"Hello readable world!")


def test_discover_files_kind_tagging(tmp_path):
    """Verify all kinds are correctly tagged: docker, ci, firebase, config, code, other."""
    cases = {
        # docker: Dockerfile*, docker-compose*.yml/yaml
        "Dockerfile": "docker",
        "Dockerfile.dev": "docker",
        "docker-compose.yml": "docker",
        "docker-compose.prod.yaml": "docker",
        # ci: .github/workflows/*.yml/yaml
        ".github/workflows/ci.yml": "ci",
        ".github/workflows/deploy.yaml": "ci",
        # firebase: firebase.json, .firebaserc, *.rules
        "firebase.json": "firebase",
        ".firebaserc": "firebase",
        "firestore.rules": "firebase",
        "storage.rules": "firebase",
        # config: *.env, .env*, *.yaml, *.yml, *.json, *.toml, *.ini, *.conf
        ".env": "config",
        ".env.local": "config",
        "custom.env": "config",
        "config.yaml": "config",
        "service.yml": "config",
        "settings.json": "config",
        "pyproject.toml": "config",
        "setup.ini": "config",
        "app.conf": "config",
        # code: *.py, *.js, *.ts
        "main.py": "code",
        "index.js": "code",
        "types.ts": "code",
        # other: everything else
        "README.md": "other",
        "notes.txt": "other",
    }

    for rel_path in cases:
        p = tmp_path / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("content", encoding="utf-8")

    files = discover_files(tmp_path)
    kind_map = {f.path: f.kind for f in files}

    for rel_path, expected_kind in cases.items():
        assert kind_map[rel_path] == expected_kind, f"Expected {rel_path} to be {expected_kind}, got {kind_map[rel_path]}"


def test_discover_files_single_file_input(tmp_path):
    """Verify discover_files works when given a single file path."""
    single = tmp_path / "script.py"
    single.write_text("print('hello')", encoding="utf-8")

    res = discover_files(single)
    assert len(res) == 1
    assert isinstance(res[0], ProjectFile)
    assert res[0].path == "script.py"
    assert res[0].kind == "code"
    assert res[0].size > 0

    # Single binary file
    bin_file = tmp_path / "blob.dat"
    bin_file.write_bytes(b"\x00\x01\x02")
    assert discover_files(bin_file) == []

    # Single oversized file
    large = tmp_path / "huge.txt"
    large.write_bytes(b"A" * (1024 * 1024 + 10))
    assert discover_files(large) == []

    # Single file matching exclude
    assert discover_files(single, exclude=["*.py"]) == []


def test_discover_files_output_is_sorted(tmp_path):
    """Verify output is sorted deterministically by path."""
    filenames = ["z_last.py", "a_first.py", "m_mid.py", "b/sub.py", "a/sub.py"]
    for fn in filenames:
        p = tmp_path / fn
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("code", encoding="utf-8")

    files = discover_files(tmp_path)
    paths = [f.path for f in files]

    assert paths == sorted(paths)


def test_discover_files_symlinks_not_followed(tmp_path):
    """Verify symlinks (files and directories) are not followed."""
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    real_file = real_dir / "real.py"
    real_file.write_text("real content", encoding="utf-8")

    # Try creating OS symlink
    symlink_created = False
    try:
        sym_file = tmp_path / "symlink.py"
        sym_file.symlink_to(real_file)
        sym_dir = tmp_path / "sym_dir"
        sym_dir.symlink_to(real_dir, target_is_directory=True)
        symlink_created = True
    except OSError:
        pass

    if symlink_created:
        files = discover_files(tmp_path)
        paths = [f.path for f in files]
        assert "symlink.py" not in paths
        assert not any(p.startswith("sym_dir") for p in paths)
        assert "real_dir/real.py" in paths

    # In addition, test via mock to guarantee coverage even when unprivileged on Windows
    orig_islink = os.path.islink
    fake_link = str(tmp_path / "mocked_symlink.py")
    (tmp_path / "mocked_symlink.py").write_text("mocked", encoding="utf-8")

    def mock_islink(path):
        if os.path.abspath(path) == os.path.abspath(fake_link):
            return True
        return orig_islink(path)

    with patch("os.path.islink", side_effect=mock_islink):
        files = discover_files(tmp_path)
        paths = [f.path for f in files]
        assert "mocked_symlink.py" not in paths