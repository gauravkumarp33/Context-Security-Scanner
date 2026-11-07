# Context-Aware Security Scanner

Context-Aware Security Scanner finds exposed credentials, insecure code patterns, and risky configuration in a project. It attaches environment evidence to each finding so developers can see why an issue was classified as production, local testing, or unknown. The Python scanner powers the CLI, the VS Code extension, and the GitHub Actions workflow.

## The problem

A permissive Firebase rule in a local fixture and the same rule in a deployed service can produce identical pattern matches. They carry different risks. Treating every match alike adds noise, while assuming that every file under `tests/` is harmless can hide a real credential or a file that is actually deployed.

## How the scanner helps

The scanner discovers eligible files, applies security rules, and uses project configuration and path clues to classify each finding. The built-in rules cover examples such as hardcoded credentials, unsafe code execution, disabled TLS verification, permissive Firebase rules, exposed database ports, and unpinned GitHub Actions. Findings include a location, severity, recommendation, environment, confidence score, and classification evidence when available.

For example, Firebase configuration can identify a referenced rules file as deployed. A local fixture with the same insecure rule may receive a lower severity when there is enough local-testing evidence. A real secret keeps its severity when classified as local testing, and an unknown environment keeps the rule's base severity. If local-only and deployment evidence conflict, the scanner surfaces the conflict and raises severity.

## Features at a glance

- **Security checks** for exposed secrets, insecure code patterns, and risky configuration.
- **Context-aware findings** with environment, confidence, evidence, and suggested fixes.
- **VS Code scanning** for a workspace or the current file, with automatic scans on save, result filters, and jump-to-code navigation.
- **CLI and CI scanning** with JSON or terminal reports, path exclusions, and severity thresholds for merge or deployment gates.
- **Optional Semgrep and Gitleaks checks** alongside the built-in rules.

## Install the Python scanner

Use Python 3.9 or later. Run these commands in a terminal with your preferred Python environment active:

```bash
git clone https://github.com/gauravkumarp33/Context-Security-Scanner.git
cd Context-Security-Scanner
python -m pip install .
python -m scanner scan tests/fixtures/vulnerable_project --format human
```

The last command scans a bundled fixture so you can see a finding and its evidence. The installation also provides the `code-security-scanner` command. If that command is outside your shell's PATH, use `python -m scanner` with the same arguments.

## Scan from the CLI

Run the scanner against a project directory or a single file. Use `.` to scan the current directory.

```bash
# Scan the current project and print a readable report
code-security-scanner scan . --format human

# Scan another project or a single file
code-security-scanner scan "path/to/project" --format human
code-security-scanner scan "path/to/project/app.py" --format human

# Skip files matching these patterns
code-security-scanner scan . --exclude "tests/*" "fixtures/*"

# Save a JSON report to a file
code-security-scanner scan . --format json -o scan-results.json

# Return exit code 1 if any finding is high or critical
code-security-scanner scan . --format human --fail-on high
```

JSON is the default format. The output is a findings array described by the [finding schema](schema/finding.schema.json). Without `-o`, the report goes to stdout and diagnostic messages go to stderr.

| Exit code | Meaning |
| --- | --- |
| `0` | The scan completed and no finding met the configured threshold, or no threshold was set. |
| `1` | The scan completed and at least one finding met or exceeded `--fail-on`. |
| `2` | The scan failed or was incomplete, for example because the target was invalid or an enabled detector failed. |

### Optional detectors

The default scan uses the bundled regex rules. Install the corresponding executable and put it on PATH before enabling [Semgrep rules](rules/semgrep/) or the [Gitleaks configuration](rules/gitleaks.toml).

```bash
code-security-scanner scan . --enable-semgrep --enable-gitleaks
```

An enabled detector that is missing or fails makes the scan incomplete and returns exit code `2`.

## Install and use the VS Code extension

Use VS Code 1.80 or later and [install the Python scanner](#install-the-python-scanner) first.

### Download and install the VSIX

Look for `context-security-scanner-0.1.0.vsix` under **Assets** on [GitHub Releases](https://github.com/gauravkumarp33/Context-Security-Scanner/releases). If a package is available, download it and run this command from the folder where you saved it:

```bash
code --install-extension "context-security-scanner-0.1.0.vsix"
```

You can also open **Extensions** in VS Code, select the **…** menu, choose **Install from VSIX…**, and select the downloaded file. See the [VSIX installation instructions](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace#_install-from-a-vsix).

### Build the VSIX from source

If there is no release asset, install Node.js and npm and run these commands from the repository root:

```bash
cd vscode-extension
npm ci
npx --yes @vscode/vsce package
```

Run the same installation command from `vscode-extension/` after the build. See the [VS Code packaging guide](https://code.visualstudio.com/api/working-with-extensions/publishing-extension).

### Scan in VS Code

Open the project you want to scan and use the Command Palette:

- **Security Scanner: Scan Workspace** scans the first workspace folder. The status bar also starts a workspace scan.
- **Security Scanner: Scan Current File** scans the active file. Automatic scans on save are enabled by default.

Findings appear in the **Security Findings** tree and **Problems** panel. When a scan finds issues, a results panel opens by default with findings grouped by file and filters for reviewing them. Select a finding to jump to its source line. The **Security Scanner** Output channel shows scan status.

The extension runs `python -m scanner` with the CLI provider by default. If you installed the scanner in a virtual environment, set `securityScanner.pythonPath` to the full path to that environment's Python executable. Use `securityScanner.autoScanOnSave` to control scans on save and `securityScanner.showPanelOnScan` to control whether the results panel opens automatically. See the [extension README](vscode-extension/README.md) for the full settings example and development setup.

## Run scans in GitHub Actions

This repository's [workflow](.github/workflows/security-scan.yml) runs on pushes and pull requests targeting `main`. It runs Python tests, checks that the installed package contains its rule resources, compiles and tests the extension, and runs the CLI scan with `--fail-on high`.

For another repository, add the following to `.github/workflows/security-scan.yml`. Replace `SCANNER_COMMIT_SHA` with a commit SHA from the scanner repository before enabling the workflow.

```yaml
name: Security scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: "3.11"
      - name: Install the scanner
        run: python -m pip install "git+https://github.com/gauravkumarp33/Context-Security-Scanner.git@SCANNER_COMMIT_SHA"
      - name: Scan the repository
        run: python -m scanner scan . --format human --fail-on high
```

To make the scan a merge gate, require the `scan` job in your branch protection or ruleset. In a delivery pipeline, make deployment depend on the successful scan job. Exit code `1` identifies findings at the threshold, while exit code `2` identifies a scanner or detector failure.

## Configure project context and exceptions

Add `scanner.config.json` to the root of the project being scanned to describe paths that follow your team's conventions:

```json
{
  "productionFiles": ["infra/live/**", "config/service.yaml"],
  "localOnlyFiles": ["tests/**", "fixtures/**"]
}
```

The scanner also uses Firebase configuration, supported Docker Compose references, and GitHub Actions deployment clues. If you need a project exception, use `rules/exceptions.yaml` with a file glob, rule ID, reason, and expiry date. Active exceptions leave findings visible and lower their severity. Expired exceptions are ignored with a warning. See the [example exceptions file](rules/exceptions.yaml).

## Privacy and limitations

- Scans run on the machine executing the CLI or the CI runner. The scanner omits raw matched secret values from its findings and sanitizes external detector errors. Reports still contain file paths and security details.
- Classification is heuristic. File discovery is separate from classification. Name tokens such as `prod` and `tests` are context clues, and GitHub Actions deployment references currently use a fixed list of recognized filenames. A branch trigger alone does not establish deployment. Use explicit path patterns for custom filenames, deployment scripts, or generated paths that the classifier cannot resolve.
- Directory discovery skips binary files, symlinks, files larger than 1 MB, and common dependency or build directories. Pattern matching and the supported context sources can produce false positives or miss issues. Review the evidence before acting on a finding.

## Develop and contribute

Install the development dependencies and run the Python checks from the repository root. From there you can also verify the wheel and source distribution, including a scan from the installed wheel outside the checkout.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m pip install "setuptools>=68" wheel
python scripts/package_smoke.py
```

For extension development, run `npm ci` and `npm test` in `vscode-extension/`. To try changes in an Extension Development Host, open the repository root in VS Code and run the **Launch Extension** debug configuration with **F5**. It opens the bundled vulnerability fixture.

- [Python scanner](scanner/) contains the CLI, file discovery, context classification, and rule execution.
- [Rules](rules/) contains the built-in detections and example exceptions.
- [VS Code extension](vscode-extension/) contains the editor integration and results panel.
- [Tests](tests/) contains regression tests and sample projects.
