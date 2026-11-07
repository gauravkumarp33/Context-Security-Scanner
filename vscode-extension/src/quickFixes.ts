import { execFile } from 'child_process';
import * as vscode from 'vscode';

const titles: ReadonlyMap<string, string> = new Map([
  ['code-debug-mode', 'Fix with Context Security Scanner: Read DEBUG from the environment (default: off)'],
  ['code-subprocess-shell', 'Fix with Context Security Scanner: Set shell=False'],
]);

interface PlannedFix {
  index: number;
  start: [number, number];
  end: [number, number];
  replacement: string;
  importLine: number | null;
}

function runPlanner(executable: string, args: string[], input: string): Promise<PlannedFix[]> {
  return new Promise((resolve, reject) => {
    const child = execFile(executable, args, {
      encoding: 'utf8',
      timeout: 3000,
      windowsHide: true,
    }, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (error) {
        reject(error);
      }
    });
    child.stdin?.on('error', () => { /* The execFile callback handles process failure. */ });
    child.stdin?.end(input, 'utf8');
  });
}

export function registerQuickFixes(context: vscode.ExtensionContext): vscode.Disposable {
  const helper = vscode.Uri.joinPath(context.extensionUri, 'python', 'quick_fixes.py').fsPath;
  return vscode.languages.registerCodeActionsProvider(
    { language: 'python', scheme: 'file' },
    {
      async provideCodeActions(document, _range, actionContext, token) {
        const diagnostics = actionContext.diagnostics.filter(diagnostic =>
          diagnostic.source === 'Security Scanner' &&
          typeof diagnostic.code === 'string' &&
          titles.has(diagnostic.code),
        );
        if (!diagnostics.length || token.isCancellationRequested) {
          return [];
        }

        const version = document.version;
        const input = JSON.stringify({
          source: document.getText(),
          diagnostics: diagnostics.map(diagnostic => [diagnostic.code, diagnostic.range.start.line + 1]),
        });
        const python = vscode.workspace.getConfiguration('securityScanner', document.uri)
          .get('pythonPath', 'python').trim() || 'python';
        const args = ['-I', '-X', 'utf8', helper];
        let fixes: PlannedFix[];
        try {
          fixes = python === 'py -3'
            ? await runPlanner('py', ['-3', ...args], input)
            : await runPlanner(python, args, input);
        } catch (error) {
          if (process.platform !== 'win32' ||
              !['python', 'python3'].includes(python) ||
              (error as NodeJS.ErrnoException).code !== 'ENOENT') {
            return [];
          }
          try {
            fixes = await runPlanner('py', ['-3', ...args], input);
          } catch {
            return [];
          }
        }
        if (token.isCancellationRequested || document.version !== version) {
          return [];
        }

        return fixes.map(fix => {
          const diagnostic = diagnostics[fix.index];
          const action = new vscode.CodeAction(titles.get(diagnostic.code as string)!, vscode.CodeActionKind.QuickFix);
          action.diagnostics = [diagnostic];
          const edit = new vscode.WorkspaceEdit();
          edit.replace(document.uri, new vscode.Range(...fix.start, ...fix.end), fix.replacement);
          if (fix.importLine !== null) {
            const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';
            edit.insert(document.uri, new vscode.Position(fix.importLine, 0), 'import os' + eol);
          }
          action.edit = edit;
          return action;
        });
      },
    },
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
  );
}
