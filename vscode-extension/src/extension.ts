import * as child_process from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { parseScanResult } from './parse';
import { CliFindingsProvider, MockFindingsProvider } from './provider';
import { SecurityFindingsTreeProvider } from './tree';
import { Finding, FindingsProvider, ScanResult, Severity } from './types';

function mapSeverityToDiagnostic(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

/**
 * Resolves the URI for a finding's file relative to workspace or mock sample workspace.
 */
function resolveFindingUri(
  finding: Finding,
  scanRoot?: string | vscode.WorkspaceFolder,
  extensionContext?: vscode.ExtensionContext
): vscode.Uri | undefined {
  if (path.isAbsolute(finding.file)) {
    if (fs.existsSync(finding.file)) {
      return vscode.Uri.file(finding.file);
    }
  }

  const rootPath =
    typeof scanRoot === 'string'
      ? scanRoot
      : scanRoot
      ? scanRoot.uri.fsPath
      : undefined;

  // 1. Resolve relative to scan root
  if (rootPath) {
    const candidate = path.resolve(rootPath, finding.file);
    if (fs.existsSync(candidate)) {
      return vscode.Uri.file(candidate);
    }

    // 1b. Check if scan root contains mock/sample-workspace/
    const sampleInWorkspace = path.join(
      rootPath,
      'mock',
      'sample-workspace',
      finding.file
    );
    if (fs.existsSync(sampleInWorkspace)) {
      return vscode.Uri.file(sampleInWorkspace);
    }

    const sampleInExtSubdir = path.join(
      rootPath,
      'vscode-extension',
      'mock',
      'sample-workspace',
      finding.file
    );
    if (fs.existsSync(sampleInExtSubdir)) {
      return vscode.Uri.file(sampleInExtSubdir);
    }
  }

  // 2. Check workspace folders
  if (vscode.workspace.workspaceFolders) {
    for (const folder of vscode.workspace.workspaceFolders) {
      const candidate = path.resolve(folder.uri.fsPath, finding.file);
      if (fs.existsSync(candidate)) {
        return vscode.Uri.file(candidate);
      }
    }
  }

  // 3. Check extension directory sample workspace
  if (extensionContext) {
    const extSample = path.join(
      extensionContext.extensionPath,
      'mock',
      'sample-workspace',
      finding.file
    );
    if (fs.existsSync(extSample)) {
      return vscode.Uri.file(extSample);
    }
  }

  // 4. Fallback: if rootPath is available, return candidate even if not existing yet on disk
  if (rootPath) {
    return vscode.Uri.file(path.resolve(rootPath, finding.file));
  }
  if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
    return vscode.Uri.file(path.resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, finding.file));
  }

  return undefined;
}

function createDiagnostic(finding: Finding): vscode.Diagnostic {
  const confidencePct = Math.round((finding.confidence ?? 0) * 100);
  let messageText = `[${finding.rule_id}] ${finding.message} | Environment: ${finding.environment || 'unknown'} (${confidencePct}%) | Fix: ${finding.recommendation || 'None'}`;
  if (finding.evidence && finding.evidence.length > 0) {
    messageText += ` | Evidence: ${finding.evidence.join('; ')}`;
  }
  const lineIdx = Math.max(0, (finding.line || 1) - 1);
  const range = new vscode.Range(lineIdx, 0, lineIdx, 1000);

  const diagnostic = new vscode.Diagnostic(
    range,
    messageText,
    mapSeverityToDiagnostic(finding.severity)
  );
  diagnostic.source = 'Security Scanner';
  diagnostic.code = finding.rule_id;
  return diagnostic;
}

/**
 * Resolves the repository root containing the 'scanner' Python module.
 * Guaranteed to point to the repository root, NOT the extension folder or workspace subfolder.
 */
export function getRepoRoot(customScannerRoot?: string, workspaceFolder?: vscode.WorkspaceFolder): string {
  // 1. Explicit user setting
  if (customScannerRoot && customScannerRoot.trim().length > 0) {
    const custom = path.resolve(customScannerRoot.trim());
    if (fs.existsSync(custom)) {
      return custom;
    }
  }

  // 2. Parent directory of extension (extension is in <repo>/vscode-extension)
  // When compiled into out/, __dirname is <repo>/vscode-extension/out
  const fromDirname = path.resolve(__dirname, '..', '..');
  if (fs.existsSync(path.join(fromDirname, 'scanner'))) {
    return fromDirname;
  }
  const fromParent = path.resolve(__dirname, '..');
  if (fs.existsSync(path.join(fromParent, 'scanner'))) {
    return fromParent;
  }

  // 3. Walk up from workspaceFolder
  if (workspaceFolder) {
    let curr = path.resolve(workspaceFolder.uri.fsPath);
    for (let i = 0; i < 6; i++) {
      if (fs.existsSync(path.join(curr, 'scanner'))) {
        return curr;
      }
      const parent = path.dirname(curr);
      if (parent === curr) break;
      curr = parent;
    }
  }

  // 4. Walk up from any open workspace folders
  if (vscode.workspace.workspaceFolders) {
    for (const folder of vscode.workspace.workspaceFolders) {
      let curr = path.resolve(folder.uri.fsPath);
      for (let i = 0; i < 6; i++) {
        if (fs.existsSync(path.join(curr, 'scanner'))) {
          return curr;
        }
        const parent = path.dirname(curr);
        if (parent === curr) break;
        curr = parent;
      }
    }
  }

  return fromDirname;
}

/**
 * Spawns the Python security scanner CLI with:
 * 1. cwd set to repository root containing 'scanner'
 * 2. command and exit code logged without retaining raw findings in the OutputChannel
 * 3. target scan path set to absolute path of workspace folder
 */
export function spawnCliScan(
  targetScanPath: string,
  workspaceFolder: vscode.WorkspaceFolder | undefined,
  outputChannel: vscode.OutputChannel
): Promise<ScanResult> {
  return new Promise<ScanResult>((resolve, reject) => {
    const config = vscode.workspace.getConfiguration('securityScanner');
    const pythonPath = config.get<string>('pythonPath', 'python').trim();
    const scannerRoot = config.get<string>('scannerRoot', '');

    // 1. Ensure cwd points to the root of the main repository, NOT extension folder or workspace subfolder
    const cwd = getRepoRoot(scannerRoot, workspaceFolder);

    // 3. Absolute path of target workspace folder
    const absoluteTarget = path.resolve(targetScanPath);

    // Bring Output channel into focus so it is never blank or hidden
    outputChannel.show(true);

    const spawnWithExe = (exeCommand: string, extraArgs: string[], onFallback?: (err: Error) => void) => {
      let exe = exeCommand;
      let prefixArgs = [...extraArgs];
      if (exeCommand === 'py -3') {
        exe = 'py';
        prefixArgs = ['-3', ...prefixArgs];
      }

      const args = [...prefixArgs, '-m', 'scanner', 'scan', absoluteTarget, '--format', 'json'];
      const fullCommand = `${exe} ${args.map((a) => (a.includes(' ') ? `"${a}"` : a)).join(' ')}`;

      outputChannel.appendLine(`\n============================================================`);
      outputChannel.appendLine(`[Security Scanner] Spawning CLI Process`);
      outputChannel.appendLine(`  Command : ${fullCommand}`);
      outputChannel.appendLine(`  CWD     : ${cwd}`);
      outputChannel.appendLine(`  Target  : ${absoluteTarget}`);
      outputChannel.appendLine(`============================================================`);

      const child = child_process.spawn(exe, args, {
        cwd,
        shell: false,
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (chunk: Buffer | string) => {
        stdout += chunk.toString();
      });

      child.stderr.on('data', (chunk: Buffer | string) => {
        stderr += chunk.toString();
      });

      child.on('error', (err: any) => {
        if (onFallback) {
          onFallback(err);
        } else {
          outputChannel.appendLine(`[Security Scanner] Spawn Error: ${err.message}`);
          reject(new Error(`Failed to start scanner CLI "${exe}": ${err.message}`));
        }
      });

      child.on('close', (code: number | null) => {
        // Log stream sizes only; raw output could contain user data.
        outputChannel.appendLine(`[Security Scanner] Exit Code: ${code}`);
        outputChannel.appendLine(`[Security Scanner] Received ${stdout.length} stdout and ${stderr.length} stderr characters.`);
        outputChannel.appendLine(`============================================================\n`);

        if (code === 2) {
          const diagnostic = 'Scanner reported an incomplete scan (exit code 2). Run the same target from the CLI to view diagnostics.';
          outputChannel.appendLine(`[ERROR] ${diagnostic}`);
          reject(new Error(diagnostic));
          return;
        }

        if (code === 2) {
          const diagnostic = stderr.trim() || 'Scanner reported an incomplete scan.';
          outputChannel.appendLine(`[ERROR] ${diagnostic}`);
          reject(new Error(diagnostic));
          return;
        }

        // Parse stdout only; non-zero exit code is not failure if stdout has valid JSON
        try {
          const scanResult = parseScanResult(stdout);
          outputChannel.appendLine(
            `[Security Scanner] Successfully parsed ${scanResult.findings.length} finding(s).`
          );
          resolve(scanResult);
        } catch (parseErr) {
          const errMsg = `Scanner CLI output was not valid JSON (exit code ${code}).`;
          outputChannel.appendLine(`[ERROR] ${errMsg}`);
          reject(new Error(errMsg));
        }
      });
    };

    spawnWithExe(pythonPath, [], (primaryErr) => {
      if (process.platform === 'win32' && (pythonPath === 'python' || pythonPath === 'python3')) {
        outputChannel.appendLine(
          `[Security Scanner] Primary executable "${pythonPath}" failed (${primaryErr.message}). Falling back to "py -3"...`
        );
        spawnWithExe('py -3', []);
      } else {
        outputChannel.appendLine(`[ERROR] Failed to start scanner CLI "${pythonPath}": ${primaryErr.message}`);
        reject(new Error(`Failed to start scanner CLI "${pythonPath}": ${primaryErr.message}`));
      }
    });
  });
}

export function activate(context: vscode.ExtensionContext) {
  // Output Channel for diagnostic and scan logs
  const outputChannel = vscode.window.createOutputChannel('Security Scanner');
  outputChannel.appendLine('[Security Scanner] Extension activated.');
  context.subscriptions.push(outputChannel);

  // Diagnostic Collection
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection('security-scanner');
  context.subscriptions.push(diagnosticCollection);

  // Tree View Data Provider
  const treeDataProvider = new SecurityFindingsTreeProvider();
  const treeViewPrimary = vscode.window.createTreeView('securityFindings', {
    treeDataProvider,
    showCollapseAll: true,
  });
  const treeViewExplorer = vscode.window.createTreeView(
    'securityFindingsExplorer',
    {
      treeDataProvider,
      showCollapseAll: true,
    }
  );
  context.subscriptions.push(treeViewPrimary, treeViewExplorer);

  // Status Bar Item
  const statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.text = '$(shield) Security Scanner';
  statusBarItem.tooltip = 'Click to run Security Scanner';
  statusBarItem.command = 'security-scanner.scanWorkspace';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // In-memory cache of current findings
  let activeFindings: Finding[] = [];

  // Helper to get active provider
  const getProvider = (): FindingsProvider => {
    const config = vscode.workspace.getConfiguration('securityScanner');
    const providerType = config.get<string>('provider', 'cli');
    const pythonPath = config.get<string>('pythonPath', 'python');
    const scannerRoot = config.get<string>('scannerRoot', '');

    if (providerType === 'cli') {
      outputChannel.appendLine(
        `[Security Scanner] Using CLI provider (pythonPath: "${pythonPath}", scannerRoot: "${scannerRoot || '<auto>'}")`
      );
      return {
        scan: (wf: vscode.WorkspaceFolder) => spawnCliScan(wf.uri.fsPath, wf, outputChannel),
        scanFile: (fileUri: vscode.Uri, wf?: vscode.WorkspaceFolder) =>
          spawnCliScan(fileUri.fsPath, wf, outputChannel),
      };
    }

    outputChannel.appendLine('[Security Scanner] Using Mock findings provider.');
    return new MockFindingsProvider();
  };

  // Command: Open Finding in Editor
  const openFindingCommand = vscode.commands.registerCommand(
    'security-scanner.openFinding',
    async (finding: Finding, explicitScanRoot?: string) => {
      try {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        const scanRoot =
          explicitScanRoot ||
          (workspaceFolders && workspaceFolders.length > 0
            ? workspaceFolders[0].uri.fsPath
            : undefined);

        const targetUri = resolveFindingUri(
          finding,
          scanRoot,
          context
        );

        if (!targetUri || !fs.existsSync(targetUri.fsPath)) {
          const displayedPath = targetUri ? targetUri.fsPath : finding.file;
          vscode.window.showErrorMessage(
            `Security Scanner: File not found: ${displayedPath}`
          );
          outputChannel.appendLine(
            `[WARN] Could not open file for finding ${finding.rule_id}: ${displayedPath}`
          );
          return;
        }

        const doc = await vscode.workspace.openTextDocument(targetUri);
        // Note: convert line to 0-based (finding.line is 1-based, VS Code Position is 0-based)
        const lineIdx = Math.max(0, (finding.line || 1) - 1);
        const pos = new vscode.Position(lineIdx, 0);

        const editor = await vscode.window.showTextDocument(doc, {
          selection: new vscode.Range(pos, pos),
          preview: false,
        });

        editor.revealRange(
          new vscode.Range(pos, pos),
          vscode.TextEditorRevealType.InCenter
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(
          `Security Scanner: Failed to open finding file: ${msg}`
        );
        outputChannel.appendLine(`[ERROR] Failed to open finding file: ${msg}`);
      }
    }
  );
  context.subscriptions.push(openFindingCommand);

  // Command: Scan Workspace
  const scanWorkspaceCommand = vscode.commands.registerCommand(
    'security-scanner.scanWorkspace',
    async () => {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showWarningMessage(
          'Security Scanner: Please open a workspace or folder to scan.'
        );
        return;
      }

      const activeFolder = workspaceFolders[0];
      const scanRoot = path.resolve(activeFolder.uri.fsPath);

      // Make sure Output Channel is visible immediately
      outputChannel.show(true);

      // Update status bar: Scanning
      statusBarItem.text = '$(sync~spin) Security Scanner: Scanning...';
      statusBarItem.tooltip = 'Scanning workspace for context security issues...';
      outputChannel.appendLine(
        `\n[Security Scanner] Starting scan on workspace: ${scanRoot}`
      );

      try {
        const provider = getProvider();
        const scanResult = await provider.scan(activeFolder);
        activeFindings = scanResult.findings;

        outputChannel.appendLine(
          `[Security Scanner] Scan completed successfully. Found ${activeFindings.length} issue(s).`
        );

        // 1. Update Tree View with findings and scan root
        treeDataProvider.setFindings(activeFindings, scanRoot);

        // 2. Clear previous diagnostics and populate new ones
        diagnosticCollection.clear();
        const diagnosticsByFile = new Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[] }>();

        for (const finding of activeFindings) {
          const fileUri = resolveFindingUri(finding, scanRoot, context);
          if (!fileUri) {
            continue;
          }

          const fileKey = fileUri.toString();
          if (!diagnosticsByFile.has(fileKey)) {
            diagnosticsByFile.set(fileKey, { uri: fileUri, diags: [] });
          }

          diagnosticsByFile.get(fileKey)!.diags.push(createDiagnostic(finding));
        }

        for (const { uri, diags } of diagnosticsByFile.values()) {
          diagnosticCollection.set(uri, diags);
        }

        // 3. Update Status Bar: Complete
        statusBarItem.text = `$(shield) Security Scanner: ${activeFindings.length} finding(s)`;
        statusBarItem.tooltip = `Scan complete. Found ${activeFindings.length} issue(s). Click to re-run.`;

        vscode.window.showInformationMessage(
          `Security Scanner: Scan completed. Found ${activeFindings.length} finding(s).`
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        outputChannel.appendLine(`[ERROR] Scan failed: ${msg}`);

        // Update Status Bar: Error
        statusBarItem.text = '$(alert) Security Scanner: Scan failed';
        statusBarItem.tooltip = `Scan failed: ${msg}. Click to re-try.`;

        vscode.window.showErrorMessage(`Security Scanner scan failed: ${msg}`);
      }
    }
  );
  context.subscriptions.push(scanWorkspaceCommand);

  // Command: Scan Single File (Feature 5)
  const scanSingleFile = async (documentUri: vscode.Uri) => {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    const activeFolder = workspaceFolders ? workspaceFolders[0] : undefined;
    const scanRoot = activeFolder ? path.resolve(activeFolder.uri.fsPath) : path.resolve(path.dirname(documentUri.fsPath));

    outputChannel.show(true);
    statusBarItem.text = '$(sync~spin) Security Scanner: Scanning file...';
    outputChannel.appendLine(
      `[Security Scanner] Scanning single file: ${path.resolve(documentUri.fsPath)}`
    );

    try {
      const provider = getProvider();
      const scanResult = await provider.scanFile(documentUri, activeFolder);
      const newFileFindings = scanResult.findings;

      // Update diagnostics for this specific file
      const fileDiagnostics = newFileFindings.map((f) => createDiagnostic(f));
      diagnosticCollection.set(documentUri, fileDiagnostics);

      // Merge new findings into active findings cache
      const docPathNorm = documentUri.fsPath.replace(/\\/g, '/').toLowerCase();
      activeFindings = activeFindings.filter((f) => {
        const fUri = resolveFindingUri(f, scanRoot, context);
        if (!fUri) {
          return true;
        }
        return fUri.fsPath.replace(/\\/g, '/').toLowerCase() !== docPathNorm;
      });
      activeFindings.push(...newFileFindings);

      // Update tree view with scan root
      treeDataProvider.setFindings(activeFindings, scanRoot);

      // Update status bar
      statusBarItem.text = `$(shield) Security Scanner: ${activeFindings.length} finding(s)`;
      statusBarItem.tooltip = `Security Scanner active: ${activeFindings.length} finding(s).`;
      outputChannel.appendLine(
        `[Security Scanner] Single-file scan completed for ${path.basename(documentUri.fsPath)}. Found ${newFileFindings.length} issue(s).`
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      outputChannel.appendLine(`[ERROR] Single-file scan failed: ${msg}`);
      statusBarItem.text = `$(shield) Security Scanner: ${activeFindings.length} finding(s)`;
    }
  };

  const scanFileCommand = vscode.commands.registerCommand(
    'security-scanner.scanFile',
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.uri.scheme !== 'file') {
        vscode.window.showWarningMessage(
          'Security Scanner: Please open a file to scan.'
        );
        return;
      }
      await scanSingleFile(editor.document.uri);
    }
  );
  context.subscriptions.push(scanFileCommand);

  // Feature 5: Automatic debounced scan on save
  let saveDebounceTimer: NodeJS.Timeout | undefined;
  const onSaveSubscription = vscode.workspace.onDidSaveTextDocument(
    async (document: vscode.TextDocument) => {
      if (document.uri.scheme !== 'file') {
        return;
      }

      const config = vscode.workspace.getConfiguration('securityScanner');
      const autoScan = config.get<boolean>('autoScanOnSave', true);
      if (!autoScan) {
        return;
      }

      if (saveDebounceTimer) {
        clearTimeout(saveDebounceTimer);
      }

      saveDebounceTimer = setTimeout(async () => {
        await scanSingleFile(document.uri);
      }, 400);
    }
  );
  context.subscriptions.push(onSaveSubscription);
}

export function deactivate() {}
