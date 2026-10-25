# Context-Aware Security Scanner

A local Python security scanning engine with context awareness, utilized across the VS Code extension, CLI, and CI/GitHub Actions workflows.

## Shared Finding Format (Contract)

Each security finding produced by the scanner adheres to the shared contract specified below.

### Fields and Ownership

| Field | Owner | Type | Constraints / Allowed Values | Description |
|---|---|---|---|---|
| `file` | Scanner | `string` | Non-empty string | Relative file path where the security issue was identified. |
| `line` | Scanner | `integer` | `>= 1` | 1-based line number of the vulnerability location. |
| `rule_id` | Rules | `string` | Non-empty string | Unique identifier for the triggered security rule. |
| `severity` | Rules | `string` | `low` \| `medium` \| `high` \| `critical` | Security risk severity level. |
| `message` | Rules | `string` | Non-empty string | Human-readable explanation of the issue; never includes raw secret values. |
| `environment` | Classifier | `string` | `production` \| `local-testing` \| `unknown` | Classified execution environment; ambiguous input remains unknown. |
| `confidence` | Classifier | `number` | Float in range `0.0` to `1.0` | Confidence score of the environment classification. |
| `recommendation` | Rules | `string` | Non-empty string | Actionable guidance for remediating or mitigating the finding. |
| `evidence` | Classifier | `string[]` | Optional; omitted when empty | Signals that led to the environment classification. |

### Contract Guarantees

1. **No Secret Leaks:** Raw secret values must never be logged or embedded in `message` or any finding field.
2. **No Silent Suppression:** An `unknown` environment classification must never silently suppress a finding.
3. **Single Engine:** All interfaces (VS Code extension, CLI, CI) consume the same Python engine and finding schema.

## Installation & Setup

Install the package (the wheel and source distribution include built-in rules, exceptions, Semgrep YAML, Gitleaks TOML, and the finding schema):

```bash
pip install .
# For development and tests:
pip install -e '.[dev]'
```

## CLI Usage

Run a scan against any project or repository directory:

```bash
# Output JSON (default format conforming to schema)
code-security-scanner scan <path-to-project> --format json

# Or invoke directly via Python module
python -m scanner scan <path-to-project> --format json

# Human-readable terminal output
code-security-scanner scan <path-to-project> --format human

# Scan one file or exclude matching paths
code-security-scanner scan <path-to-file>
code-security-scanner scan <path-to-project> --exclude 'tests/*' 'fixtures/*'

# Fail with exit code 1 on findings at or above high severity (used in CI)
code-security-scanner scan <path-to-project> --fail-on high

# Save results to a file
code-security-scanner scan <path-to-project> --format json -o scan-results.json

# Optional external detectors (install the corresponding executable first)
code-security-scanner scan <path-to-project> --enable-semgrep
code-security-scanner scan <path-to-project> --enable-gitleaks
```

The default scan uses built-in regex rules. Semgrep rules are in `rules/semgrep/` and Gitleaks rules/configuration are in `rules/gitleaks.toml`; enable either with its flag. An enabled tool that is missing or fails makes the scan incomplete and returns exit code 2. External tools run once on the scan target and their results are mapped back to files.

Projects can add `scanner.config.json` to classify explicit paths:

```json
{
  "productionFiles": ["deploy/**", "infra/prod.yaml"],
  "localOnlyFiles": ["tests/**", "fixtures/**"]
}
```

### Exit Codes Contract

| Exit Code | Meaning | Description |
|---|---|---|
| `0` | Success | Scan completed successfully; no findings detected or findings below `--fail-on` threshold. |
| `1` | Blocking Findings | Scan completed successfully, but detected vulnerabilities meeting or exceeding `--fail-on` threshold. |
| `2` | Scanner Error | Execution failure, invalid rules, or enabled tool unavailable/failed. Diagnostics go to stderr; JSON stdout remains a findings array. |

## Context classification and privacy

Production and local/test Compose services are parsed to classify the manifest and referenced Dockerfiles/build contexts, env files, and host mounts. GitHub Actions deployment evidence requires a deployment command or a production job environment; branch triggers alone do not count. Conflicting local-only and production evidence remains visible and raises severity. Unknown classifications retain base severity, and local/test context never lowers real-secret findings. Active exceptions remain visible with a severity downgrade; expired exceptions are ignored with a warning.

Raw matched secret values are never serialized in findings or CLI output. External tool errors and configuration parse warnings are sanitized. The scanner skips binary files, files over 1 MB, symlinks, and standard dependency/build directories. Classification is heuristic and should be reviewed for deployment patterns outside the supported config formats.

To verify package resources after a wheel install, run `python scripts/package_smoke.py`.

