# Context Security Scanner - VS Code Extension

VS Code extension for the Context-Aware Security Scanner. Provides interactive workspace scanning, categorized severity tree view, rich tooltips with context classification and confidence ratings, in-editor diagnostic underlines (Problems panel integration), and seamless jump-to-source navigation.

---

## Getting Started

### 1. Installation

From the `vscode-extension` directory, install Node.js dependencies:

```bash
cd vscode-extension
npm install
```

### 2. Compilation

Compile TypeScript to JavaScript (`out/` directory):

```bash
npm run compile
```

To continuously watch and compile during development:

```bash
npm run watch
```

To run unit tests:

```bash
npm run test
```

### 3. Running & Debugging (F5)

1. Open the repository or the `vscode-extension` folder in VS Code.
2. Ensure you have run `npm install` and `npm run compile`.
3. Press **`F5`** (or go to the **Run and Debug** view and select **"Run Extension"**).
4. A new **Extension Development Host** window will open with the extension active.
5. In the Extension Development Host window:
   - Open any workspace or test folder (e.g. `vscode-extension/mock/sample-workspace`).
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) and run:
     **`Security Scanner: Scan Workspace`**
   - Alternatively, click the **`$(shield) Security Scanner`** button in the bottom status bar or in the **Security Findings** activity bar view / Explorer pane.
6. The scan results will immediately populate:
   - **Tree View:** "Security Findings" view grouped by severity (`Critical`, `High`, `Medium`, `Low`) displaying `rule_id`, `file:line`, and environment badge with confidence (`[production (95%)]`, `[unknown (20%)]`).
   - **Problems Panel & In-Editor Underlines:** Diagnostics mapped to `DiagnosticSeverity`, showing:
     `[<rule_id>] <message> | Environment: <env> | Fix: <recommendation>`
   - **Jump-to-Line:** Clicking any finding in the tree view opens the exact file and positions the cursor at the offending 1-based line number.

---

## Mock Findings & Sample Workspace

- **Mock Findings JSON:** `vscode-extension/mock/findings.mock.json`
  - Conforms strictly to `schema/finding.schema.json`.
  - Copied from `tests/fixtures/mock_findings.json`.
- **Sample Workspace:** `vscode-extension/mock/sample-workspace/`
  - Contains stub files matching the mock findings line numbers:
    - `deploy/k8s/deployment.yaml` (line 42: `API_PROD_SECRET_KEY`)
    - `tests/test_auth.py` (line 15: `mock_token`)
    - `config/service.conf` (line 8: `upstream_gateway = http://...`)

---

## How to Swap in the CLI Provider

The extension adheres to the `FindingsProvider` interface:

```typescript
export interface FindingsProvider {
  scan(workspaceFolder: vscode.WorkspaceFolder): Promise<ScanResult>;
}
```

Two production-ready providers are implemented in [`src/provider.ts`](src/provider.ts):
1. **`MockFindingsProvider`**: Default provider reading from `mock/findings.mock.json`.
2. **`CliFindingsProvider`**: Executes the Python scanner engine CLI using `child_process.spawn` (with arguments and executable passed strictly separately without a shell string).

### Method A: Via VS Code Settings (Zero Code Change)

In VS Code settings (or `.vscode/settings.json`), set:

```json
{
  "securityScanner.provider": "cli",
  "securityScanner.cliPath": "code-security-scanner"
}
```

If you installed the Python engine in a virtual environment, specify the full path:
```json
{
  "securityScanner.provider": "cli",
  "securityScanner.cliPath": "C:\\Users\\harsh\\Context-Security-Scanner\\.venv\\Scripts\\code-security-scanner.exe"
}
```

### Method B: In Code

In [`src/extension.ts`](src/extension.ts), modify `getProvider()`:

```typescript
// Replace:
return new MockFindingsProvider();

// With:
return new CliFindingsProvider('code-security-scanner');
```

The CLI provider spawns `code-security-scanner scan <path> --format json`, parses the JSON output according to the exit code contract (0 = Clean, 1 = Blocking findings detected, 2 = Scanner Error), and populates diagnostics and tree views identically.
