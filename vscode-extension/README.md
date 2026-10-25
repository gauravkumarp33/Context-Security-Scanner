# Context Security Scanner - VS Code Extension

The extension uses the Python CLI provider by default. It scans an open workspace or a single file, displays findings in a severity tree and the Problems panel, and opens findings at their source line. Classification evidence appears in finding tooltips and diagnostics.

## Install and run

Install the Python package from the repository root (`pip install .`) and ensure its Python executable is available. In `vscode-extension`, install dependencies and compile:

```bash
npm ci
npm run compile
npm test
```

Open this repository in VS Code, press F5, and run **Security Scanner: Scan Workspace**. Use **Security Scanner: Scan Current File** for a file scan. The status bar and activity bar tree show results; selecting a finding opens its file at the reported line.

## Settings

The CLI provider is the default. Configure Python and, for an extension development host, the scanner source root in VS Code settings:

```json
{
  "securityScanner.provider": "cli",
  "securityScanner.pythonPath": "C:\\path\\to\\.venv\\Scripts\\python.exe",
  "securityScanner.scannerRoot": "C:\\path\\to\\Context Security Scanner",
  "securityScanner.autoScanOnSave": true
}
```

`securityScanner.provider` also supports `mock` for previewing `mock/findings.mock.json`. The extension invokes `python -m scanner` without a shell. CLI JSON stays on stdout, scanner diagnostics go to stderr, and exit code 2 is treated as an incomplete scan.

## Privacy and limits

Finding messages, recommendations, classification evidence, CLI output, and editor diagnostics do not include raw matched secret values. The extension does not enable optional external detectors; run the CLI with `--enable-semgrep` or `--enable-gitleaks` if those tools are installed. The scanner skips binary files, files larger than 1 MB, symlinks, and common dependency/build directories. Context classification is heuristic; review evidence for deployment systems outside the supported Firebase, Compose, GitHub Actions, and scanner config patterns.

The mock findings and sample workspace remain available for preview and parser development. They are not the default provider.
