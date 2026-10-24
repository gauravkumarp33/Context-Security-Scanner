from pathlib import Path
import pytest
from scanner.filetypes import ALL_TAGS, get_file_types, list_files_by_type


def test_positive_tags_format_and_config():
    """Verify format tags (yaml, json, toml), env, and general config."""
    # YAML & Config
    res_yaml = get_file_types("config/settings.yaml")
    assert "yaml" in res_yaml
    assert "config" in res_yaml

    res_yml = get_file_types("service.yml")
    assert "yaml" in res_yml
    assert "config" in res_yml

    # JSON & Config
    res_json = get_file_types("package.json")
    assert "json" in res_json
    assert "config" in res_json

    # TOML & Config
    res_toml = get_file_types("pyproject.toml")
    assert "toml" in res_toml
    assert "config" in res_toml

    # INI & Config
    res_ini = get_file_types("setup.ini")
    assert "config" in res_ini

    # CONF & Config
    res_conf = get_file_types("app.conf")
    assert "config" in res_conf

    # ENV & Config
    for env_name in [".env", ".env.local", ".env.production", "database.env"]:
        res_env = get_file_types(env_name)
        assert "env" in res_env
        assert "config" in res_env


def test_positive_tags_docker_and_compose():
    """Verify docker and compose tags."""
    # Dockerfile variations
    assert get_file_types("Dockerfile") == {"docker"}
    assert get_file_types("Dockerfile.dev") == {"docker"}
    assert get_file_types("Dockerfile.prod") == {"docker"}
    assert get_file_types("Containerfile") == {"docker"}
    assert get_file_types("Containerfile.stage") == {"docker"}

    # Docker Compose files (multi-label: docker, compose, yaml, config)
    res_compose = get_file_types("compose.yaml")
    assert res_compose == {"yaml", "docker", "compose", "config"}

    res_docker_compose = get_file_types("docker-compose.prod.yml")
    assert res_docker_compose == {"yaml", "docker", "compose", "config"}


def test_positive_tags_ci_platforms():
    """Verify CI platform tags and umbrella CI tag."""
    # GitHub Actions
    gh = get_file_types(".github/workflows/ci.yml")
    assert gh == {"yaml", "ci", "github-actions", "config"}

    # GitLab CI
    gl = get_file_types(".gitlab-ci.yml")
    assert "gitlab-ci" in gl
    assert "ci" in gl
    assert "yaml" in gl
    assert "config" in gl

    # CircleCI
    circle = get_file_types(".circleci/config.yml")
    assert "circleci" in circle
    assert "ci" in circle
    assert "yaml" in circle

    # Bitbucket Pipelines
    bb = get_file_types("bitbucket-pipelines.yml")
    assert "bitbucket-pipelines" in bb
    assert "ci" in bb
    assert "yaml" in bb

    # Azure Pipelines
    az1 = get_file_types("azure-pipelines.yml")
    assert "azure-pipelines" in az1
    assert "ci" in az1
    assert "yaml" in az1

    az2 = get_file_types(".azure-pipelines.yaml")
    assert "azure-pipelines" in az2
    assert "ci" in az2


def test_positive_tags_kubernetes(tmp_path):
    """Verify kubernetes tag from path hints and YAML content sniffing."""
    # Path hint (k8s/ or kubernetes/)
    k8s_path = get_file_types("k8s/ingress.yaml")
    assert "kubernetes" in k8s_path
    assert "yaml" in k8s_path
    assert "config" in k8s_path

    k8s_dir_path = get_file_types("kubernetes/service.yml")
    assert "kubernetes" in k8s_dir_path

    # Content sniff: YAML containing apiVersion: and kind:
    k8s_file = tmp_path / "custom-deploy.yaml"
    k8s_file.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web-app\n",
        encoding="utf-8",
    )
    sniffed = get_file_types(k8s_file)
    assert "kubernetes" in sniffed
    assert "yaml" in sniffed
    assert "config" in sniffed


def test_positive_tags_terraform():
    """Verify terraform / IaC tags."""
    for tf_file in ["main.tf", "variables.tfvars", "terragrunt.hcl"]:
        res = get_file_types(tf_file)
        assert "terraform" in res
        assert "config" in res


def test_positive_tags_firebase():
    """Verify firebase tags."""
    for fb_file in ["firebase.json", ".firebaserc", "firestore.rules", "storage.rules"]:
        res = get_file_types(fb_file)
        assert "firebase" in res
        assert "config" in res


def test_positive_tags_secret_files():
    """Verify secret-file tags for keys, certificates, and credentials."""
    for sec_file in [
        "id_rsa",
        "id_ed25519",
        "server.key",
        "cert.pem",
        "bundle.crt",
        ".npmrc",
        ".pypirc",
        ".netrc",
    ]:
        res = get_file_types(sec_file)
        assert "secret-file" in res


def test_positive_tags_code_extensions():
    """Verify code tag for all supported programming and scripting languages."""
    code_files = [
        "main.py",
        "app.js",
        "types.ts",
        "deploy.sh",
        "script.bash",
        "server.go",
        "App.java",
        "index.php",
        "app.rb",
        "Program.cs",
    ]
    for code_file in code_files:
        res = get_file_types(code_file)
        assert "code" in res, f"Expected {code_file} to be tagged 'code', got {res}"


def test_negative_dockerfile_bak_not_docker():
    """Verify Dockerfile.bak and backup extensions are NOT tagged docker."""
    for bak in ["Dockerfile.bak", "Dockerfile.old", "Dockerfile.tmp", "Containerfile.backup"]:
        res = get_file_types(bak)
        assert "docker" not in res, f"Expected {bak} to NOT have docker tag, got {res}"


def test_negative_random_yaml_is_not_ci():
    """Verify a generic YAML file is not tagged CI."""
    for yaml_file in ["config.yaml", "service.yml", "schema.yaml", "docker-compose.yml"]:
        res = get_file_types(yaml_file)
        assert "ci" not in res, f"Expected {yaml_file} to NOT have ci tag, got {res}"


def test_negative_deployment_yml_without_apiversion_is_not_kubernetes(tmp_path):
    """Verify deployment.yml outside k8s directory without apiVersion/kind is NOT kubernetes."""
    f = tmp_path / "deployment.yml"
    f.write_text("env: production\nreplicas: 3\nimage: nginx\n", encoding="utf-8")
    res = get_file_types(f)
    assert "kubernetes" not in res
    assert "yaml" in res
    assert "config" in res


def test_windows_style_path_normalization():
    """Verify Windows backslashes normalize properly to match path rules."""
    res_gh = get_file_types(r"project\.github\workflows\ci.yml")
    assert res_gh == {"yaml", "ci", "github-actions", "config"}

    res_code = get_file_types(r"src\api\server.py")
    assert res_code == {"code"}

    res_compose = get_file_types(r"deploy\docker-compose.prod.yaml")
    assert "compose" in res_compose
    assert "docker" in res_compose


def test_empty_or_unreadable_file_handled_gracefully(tmp_path):
    """Verify empty or non-existent files do not cause errors."""
    # Non-existent path
    res_missing = get_file_types(tmp_path / "missing_file.yaml")
    assert res_missing == {"yaml", "config"}

    # Empty file
    empty_file = tmp_path / "empty.yaml"
    empty_file.touch()
    res_empty = get_file_types(empty_file)
    assert res_empty == {"yaml", "config"}


def test_list_files_by_type_end_to_end(tmp_path):
    """Verify list_files_by_type maps tags to sorted paths, skipping node_modules and binary files."""
    # Valid files
    (tmp_path / "Dockerfile").touch()
    (tmp_path / "compose.yaml").touch()
    (tmp_path / ".env").touch()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").touch()
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").touch()

    # Ignored directory: node_modules
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "bad.js").touch()

    # Binary file
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")

    # Call without types filter
    res = list_files_by_type(tmp_path)
    assert isinstance(res, dict)
    assert "docker" in res
    assert "compose" in res
    assert "code" in res
    assert "ci" in res

    assert res["docker"] == ["Dockerfile", "compose.yaml"]
    assert res["compose"] == ["compose.yaml"]
    assert res["code"] == ["src/main.py"]
    assert res["env"] == [".env"]
    assert res["github-actions"] == [".github/workflows/ci.yml"]
    assert res["ci"] == [".github/workflows/ci.yml"]

    # Verify node_modules and binary files were excluded
    all_files_listed = {f for paths in res.values() for f in paths}
    assert not any("node_modules" in f for f in all_files_listed)
    assert "binary.bin" not in all_files_listed

    # Call with types filter
    filtered = list_files_by_type(tmp_path, types={"docker", "ci"})
    assert set(filtered.keys()) == {"docker", "ci"}
    assert filtered["docker"] == ["Dockerfile", "compose.yaml"]
    assert filtered["ci"] == [".github/workflows/ci.yml"]
