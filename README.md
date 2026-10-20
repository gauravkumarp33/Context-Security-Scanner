# Context-Aware Security Scanner

A local Python security scanning engine with context awareness, utilized across the VS Code extension, CLI, and CI/GitHub Actions workflows.

## Shared Finding Format (Contract)

Each security finding produced by the scanner adheres to the shared contract specified below.

### Fields and Ownership

| Field | Owner | Type | Constraints / Allowed Values | Description |
|---|---|---|---|---|
| `file` | Member 2 (Rules) | `string` | Non-empty string | Relative file path where the security issue was identified. |
| `line` | Member 2 (Rules) | `integer` | `>= 1` | 1-based line number of the vulnerability location. |
| `rule_id` | Member 2 (Rules) | `string` | Non-empty string | Unique identifier for the triggered security rule (e.g., `SEC-ENV-001`). |
| `severity` | Member 2 (Rules) | `string` | `low` \| `medium` \| `high` \| `critical` | Security risk severity level. |
| `message` | Member 2 (Rules) | `string` | Non-empty string | Human-readable explanation of the issue. **Hard Rule:** Never include raw secrets or sensitive token values. |
| `environment` | Member 1 (Classifier) | `string` | `production` \| `local-testing` \| `unknown` | Execution environment context classified for the target file. Ambiguous input must be marked `unknown` and never silently suppress findings. |
| `confidence` | Member 1 (Classifier) | `number` | Float in range `0.0` to `1.0` | Confidence score of the environment classification. |
| `recommendation` | Member 2 (Rules) | `string` | Non-empty string | Actionable guidance for remediating or mitigating the issue. |

### Contract Guarantees

1. **No Secret Leaks:** Raw secret values must never be logged or embedded in `message` or any finding field.
2. **No Silent Suppression:** An `unknown` environment classification must never silently suppress a finding.
3. **Single Engine:** All interfaces (VS Code extension, CLI, CI) consume the same Python engine and finding schema.

## Installation & Setup

Install the package locally in editable mode:

```bash
pip install -e .
# Or with test dependencies:
pip install -e .[dev]
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

# Fail with exit code 1 on findings at or above high severity (used in CI)
code-security-scanner scan <path-to-project> --fail-on high

# Save results to a file
code-security-scanner scan <path-to-project> --format json -o scan-results.json
```

### Exit Codes Contract

| Exit Code | Meaning | Description |
|---|---|---|
| `0` | Clean / Success | Scan completed successfully; no findings detected or findings below `--fail-on` threshold. |
| `1` | Blocking Findings | Scan completed successfully, but detected vulnerabilities meeting or exceeding `--fail-on` threshold. |
| `2` | Scanner Error | Execution failure (e.g., target directory does not exist, bad CLI arguments, tool errors). |

