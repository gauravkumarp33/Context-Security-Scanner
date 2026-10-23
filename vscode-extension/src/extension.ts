import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { CliFindingsProvider, MockFindingsProvider } from './provider';
import { SecurityFindingsTreeProvider } from './tree';
import { Finding, FindingsProvider, Severity } from './types';

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
  workspaceFolder?: vscode.WorkspaceFolder,
  extensionContext?: vscode.ExtensionContext
): vscode.Uri | undefined {
  if (path.isAbsolute(finding.file)) {
    if (fs.existsSync(finding.file)) {
      return vscode.Uri.file(finding.file);
    }
  }

  // 1. Check workspace folder
  if (workspaceFolder) {
    const candidate = path.join(workspaceFolder.uri.fsPath, finding.file);
    if (fs.existsSync(candidate)) {
      return vscode.Uri.file(candidate);
    }

    // 1b. Check if workspace contains mock/sample-workspace/
    const sampleInWorkspace = path.join(
      workspaceFolder.uri.fsPath,
      'mock',
      'sample-workspace',
      finding.file
    );
    if (fs.existsSync(sampleInWorkspace)) {
      return vscode.Uri.file(sampleInWorkspace);
    }

    const sampleInExtSubdir = path.join(
      workspaceFolder.uri.fsPath,
      'vscode-extension',
      'mock',
      'sample-workspace',
      finding.file
    );
    if (fs.existsSync(sampleInExtSubdir)) {
      return vscode.Uri.file(sampleInExtSubdir);
    }
  }

  // 2. Check extension directory sample workspace
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

  // 3. Fallback to workspace uri even if file doesn't currently exist
  if (workspaceFolder) {
    return vscode.Uri.joinPath(workspaceFolder.uri, finding.file);
  }

  return undefined;
}

function createDiagnostic(finding: Finding): vscode.Diagnostic {
  // Format: "[rule_id] message | Environment: X | Fix: recommendation"
  const messageText = `[${finding.rule_id}] ${finding.message} | Environment: ${finding.environment} | Fix: ${finding.recommendation}`;
  const lineIdx = Math.max(0, finding.line - 1);
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
    const providerType = config.get<string>('provider', 'mock');
    const cliPath = config.get<string>('cliPath', 'code-security-scanner');

    if (providerType === 'cli') {
      outputChannel.appendLine(`[Security Scanner] Using CLI provider (${cliPath})`);
      return new CliFindingsProvider(cliPath);
    }

    outputChannel.appendLine('[Security Scanner] Using Mock findings provider.');
    return new MockFindingsProvider();
  };

  // Command: Open Finding in Editor
  const openFindingCommand = vscode.commands.registerCommand(
    'security-scanner.openFinding',
    async (finding: Finding) => {
      try {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        const workspaceFolder = workspaceFolders ? workspaceFolders[0] : undefined;
        const targetUri = resolveFindingUri(
          finding,
          workspaceFolder,
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
        // Note: finding.line is 1-based, VS Code Position is 0-based
        const lineIdx = Math.max(0, finding.line - 1);
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

      // Update status bar: Scanning
      statusBarItem.text = '$(sync~spin) Security Scanner: Scanning...';
      statusBarItem.tooltip = 'Scanning workspace for context security issues...';
      outputChannel.appendLine(
        `\n[Security Scanner] Starting scan on workspace: ${activeFolder.uri.fsPath}`
      );

      try {
        const provider = getProvider();
        const scanResult = await provider.scan(activeFolder);
        activeFindings = scanResult.findings;

        outputChannel.appendLine(
          `[Security Scanner] Scan completed successfully. Found ${activeFindings.length} issue(s).`
        );

        // 1. Update Tree View
        treeDataProvider.setFindings(activeFindings);

        // 2. Clear previous diagnostics and populate new ones
        diagnosticCollection.clear();
        const diagnosticsByFile = new Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[] }>();

        for (const finding of activeFindings) {
          const fileUri = resolveFindingUri(finding, activeFolder, context);
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

    statusBarItem.text = '$(sync~spin) Security Scanner: Scanning file...';
    outputChannel.appendLine(
      `[Security Scanner] Scanning single file: ${documentUri.fsPath}`
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
        const fUri = resolveFindingUri(f, activeFolder, context);
        if (!fUri) {
          return true;
        }
        return fUri.fsPath.replace(/\\/g, '/').toLowerCase() !== docPathNorm;
      });
      activeFindings.push(...newFileFindings);

      // Update tree view
      treeDataProvider.setFindings(activeFindings);

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
