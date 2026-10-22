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
| `production` | `confidence >= 0.8` | `public_access`, `debug_mode`, `disabled_tls`, `exposed_secret` | **Raise by ONE level** (capped at `critical`) |
| `production` | Any | Other / unmapped categories | Keep original severity |
| `local-testing` | `confidence >= 0.8` and `is_real_secret=False` | `insecure_config`, `test_credentials` | **Lower by at most ONE level** (never below `low`) |
| `local-testing` | `is_real_secret=True` | Any | Keep original severity (real secrets are **never** lowered) |
| `local-testing` | `confidence < 0.8` | Any | Keep original severity (treated as `unknown` for adjustment) |
| `unknown` | Any | Any | **unknown never lowers severity** (severity remains unchanged) |

> unknown never lowers severity

---

## 3. Rule Categories & Mapping

Detection rules are mapped to specific categories in `scanner/severity.py`:

| Rule ID | Category | Default Base Severity | Production Adjusted | Local-Testing Adjusted |
|---|---|---|---|---|
| `firebase-open-access` | `public_access` | `medium` | `high` | `medium` |

Unmapped rule IDs receive no category and their severity is never altered by environment policies.
