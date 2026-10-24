# Detection Rules & Severity Adjustment Policy

This document defines the environment values, rule categories, and context-aware severity adjustment policies used by the security scanner.

---

## 1. Supported Environments

The scanner classifies file contexts into three canonical environments (as defined in `schema/finding.schema.json` and `scanner/models.py`):

| Environment | Description |
|---|---|
| `production` | Deployed applications, production configurations, and cloud deployment manifests. |
| `local-testing` | Unit tests, test fixtures, test mocks, examples, and local development configurations. |
| `unknown` | Files without clear production or testing signals, or conflicting signals. |

---

## 2. Severity Adjustment Policy

Severities follow the strict order:
$$\text{low} < \text{medium} < \text{high} < \text{critical}$$

Severity values never exceed `critical` and never fall below `low`.

### Policy Matrix

| Environment | Condition | Category Set | Severity Adjustment |
|---|---|---|---|
| `production` | `confidence >= 0.8` | `debug_mode`, `disabled_tls`, `exposed_secret` | **Raise by ONE level** (capped at `critical`) |
| `production` | Any | Other / unmapped categories (including `public_access`) | Keep original severity |
| `local-testing` | `confidence >= 0.8` and `is_real_secret=False` | `insecure_config`, `test_credentials`, `public_access` | **Lower by at most ONE level** (never below `low`) |
| `local-testing` | `is_real_secret=True` | Any | Keep original severity (real secrets are **never** lowered) |
| `local-testing` | `confidence < 0.8` | Any | Keep original severity (treated as `unknown` for adjustment) |
| `unknown` | Any | Any | **unknown never lowers severity** (severity remains unchanged) |

> unknown never lowers severity

---

## 3. Rule Categories & Mapping

Detection rules are mapped to specific categories in `scanner/severity.py`:

| Rule ID | Category | Default Base Severity | Production Adjusted | Local-Testing Adjusted | Unknown Adjusted |
|---|---|---|---|---|---|
| `firebase-open-access` | `public_access` | `high` | `high` | `medium` | `high` |

Unmapped rule IDs receive no category and their severity is never altered by environment policies.

---

## 4. File-Type Tags

The scanner provides semantic, multi-label file classification in `scanner/filetypes.py` (`get_file_types(path)` and `list_files_by_type(root)`). Security detection rules and integrations (e.g. Gitleaks, Semgrep) can target files by these semantic tags:

| Tag | Matched Patterns / Criteria | Example |
|---|---|---|
| `docker` | `Dockerfile*`, `Containerfile*` (excluding `.bak`/`.tmp`), and any `compose` file | `Dockerfile.prod`, `Containerfile`, `compose.yaml` |
| `compose` | `docker-compose*.yml/yaml`, `compose*.yml/yaml` | `docker-compose.prod.yml`, `compose.yaml` |
| `ci` | Umbrella tag for all supported CI/CD platforms | `.github/workflows/deploy.yml`, `.gitlab-ci.yml` |
| `github-actions` | `.github/workflows/*.yml/yaml` | `.github/workflows/ci.yml` |
| `gitlab-ci` | `.gitlab-ci*.yml/yaml` | `.gitlab-ci.yml` |
| `circleci` | `.circleci/*.yml/yaml` | `.circleci/config.yml` |
| `bitbucket-pipelines` | `bitbucket-pipelines.yml/yaml` | `bitbucket-pipelines.yml` |
| `azure-pipelines` | `azure-pipelines*.yml/yaml`, `.azure-pipelines*.yml/yaml` | `azure-pipelines.yml` |
| `kubernetes` | Path segments `k8s/`, `kubernetes/` OR YAML containing `apiVersion:` + `kind:` (first 4 KB sniff) | `k8s/deployment.yaml`, `deploy/pod.yml` |
| `terraform` | `*.tf`, `*.tfvars`, `*.hcl` | `main.tf`, `terraform.tfvars` |
| `env` | `*.env`, `.env*` | `.env`, `.env.production` |
| `yaml` | `*.yaml`, `*.yml` | `config.yaml`, `service.yml` |
| `json` | `*.json` | `settings.json`, `firebase.json` |
| `toml` | `*.toml` | `pyproject.toml`, `gitleaks.toml` |
| `firebase` | `firebase.json`, `.firebaserc`, `*.rules` | `firestore.rules`, `firebase.json` |
| `config` | Structured config (`yaml`, `json`, `toml`, `env`, `ini`, `conf`, `cfg`, `ci`, `compose`, `k8s`, `terraform`, `firebase`) | `app.conf`, `settings.json`, `compose.yaml` |
| `code` | Source code (`.py`, `.js`, `.ts`, `.sh`, `.bash`, `.go`, `.java`, `.php`, `.rb`, `.cs`) | `server.py`, `script.sh`, `main.go` |
| `secret-file` | Keys, certs, and package credentials (`id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.crt`, `.npmrc`, `.pypirc`, `.netrc`) | `id_rsa`, `server.key`, `.npmrc` |

