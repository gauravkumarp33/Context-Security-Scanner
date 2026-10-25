import * as child_process from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { parseScanResult } from './parse';
import { FindingsProvider, ScanResult } from './types';

/**
 * Mock provider reading mock findings from local JSON file.
 */
export class MockFindingsProvider implements FindingsProvider {
  constructor(private readonly customMockPath?: string) {}

  async scan(workspaceFolder: vscode.WorkspaceFolder): Promise<ScanResult> {
    const candidatePaths: string[] = [];

    if (this.customMockPath) {
      candidatePaths.push(this.customMockPath);
    }

    // 1. Extension's own mock directory
    candidatePaths.push(
      path.join(__dirname, '..', 'mock', 'findings.mock.json')
    );

    // 2. Relative to workspace folder
    candidatePaths.push(
      path.join(workspaceFolder.uri.fsPath, 'mock', 'findings.mock.json'),
      path.join(workspaceFolder.uri.fsPath, '..', 'findings.mock.json'),
      path.join(
        workspaceFolder.uri.fsPath,
        'vscode-extension',
        'mock',
        'findings.mock.json'
      ),
      path.join(
        workspaceFolder.uri.fsPath,
        'tests',
        'fixtures',
        'mock_findings.json'
      )
    );

    let chosenPath: string | undefined;
    for (const p of candidatePaths) {
      if (fs.existsSync(p)) {
        chosenPath = p;
        break;
      }
    }

    if (!chosenPath) {
      throw new Error(
        `Mock findings file not found. Looked in: ${candidatePaths.join(', ')}`
      );
    }

    const rawContent = await fs.promises.readFile(chosenPath, 'utf8');
    return parseScanResult(rawContent);
  }

  async scanFile(fileUri: vscode.Uri, workspaceFolder?: vscode.WorkspaceFolder): Promise<ScanResult> {
    const fullResult = await this.scan(workspaceFolder || { uri: fileUri, name: 'default', index: 0 });
    const targetBase = path.basename(fileUri.fsPath).toLowerCase();
    const matching = fullResult.findings.filter((f) => {
      const fBase = path.basename(f.file).toLowerCase();
      return fBase === targetBase || fileUri.fsPath.replace(/\\/g, '/').endsWith(f.file.replace(/\\/g, '/'));
    });
    return { findings: matching };
  }
}

export interface CliProviderOptions {
  pythonPath?: string;
  scannerRoot?: string;
  outputChannel?: vscode.OutputChannel;
  cliExecutable?: string;
}

/**
 * Production CLI provider executing the Python scanner binary or module.
 * Swappable with MockFindingsProvider. Uses child_process.spawn with executable and
 * arguments passed strictly as separate items, never as a shell string.
 */
export class CliFindingsProvider implements FindingsProvider {
  private readonly pythonPath: string;
  private readonly scannerRoot: string;
  private readonly outputChannel?: vscode.OutputChannel;

  constructor(
    pythonPathOrOptions?: string | CliProviderOptions,
    scannerRoot?: string,
    outputChannel?: vscode.OutputChannel
  ) {
    if (typeof pythonPathOrOptions === 'object' && pythonPathOrOptions !== null) {
      this.pythonPath = pythonPathOrOptions.pythonPath || 'python';
      this.scannerRoot = pythonPathOrOptions.scannerRoot || '';
      this.outputChannel = pythonPathOrOptions.outputChannel;
    } else {
      this.pythonPath = pythonPathOrOptions || 'python';
      this.scannerRoot = scannerRoot || '';
      this.outputChannel = outputChannel;
    }
  }

  scan(workspaceFolder: vscode.WorkspaceFolder): Promise<ScanResult> {
    const cwd = this.resolveRepoRoot(workspaceFolder);
    return this.runCliScan(path.resolve(workspaceFolder.uri.fsPath), cwd);
  }

  scanFile(fileUri: vscode.Uri, workspaceFolder?: vscode.WorkspaceFolder): Promise<ScanResult> {
    const cwd = this.resolveRepoRoot(workspaceFolder);
    return this.runCliScan(path.resolve(fileUri.fsPath), cwd);
  }

  private resolveRepoRoot(workspaceFolder?: vscode.WorkspaceFolder): string {
    if (this.scannerRoot && this.scannerRoot.trim().length > 0) {
      return path.resolve(this.scannerRoot);
    }
    // Check parent of vscode-extension directory (__dirname is <repo>/vscode-extension/out)
    const extRepoRoot = path.resolve(__dirname, '..', '..');
    if (fs.existsSync(path.join(extRepoRoot, 'scanner'))) {
      return extRepoRoot;
    }
    if (workspaceFolder) {
      let curr = workspaceFolder.uri.fsPath;
      for (let i = 0; i < 4; i++) {
        if (fs.existsSync(path.join(curr, 'scanner'))) {
          return curr;
        }
        const parent = path.dirname(curr);
        if (parent === curr) break;
        curr = parent;
      }
    }
    return extRepoRoot;
  }

  private runCliScan(targetPath: string, cwd: string): Promise<ScanResult> {
    return new Promise<ScanResult>((resolve, reject) => {
      const configuredExe = (this.pythonPath || 'python').trim();
      const absoluteTarget = path.resolve(targetPath);

      if (this.outputChannel) {
        this.outputChannel.show(true);
      }

      const spawnProcess = (exeCommand: string, extraPrefixArgs: string[], onFallback?: (err: Error) => void) => {
        let exe = exeCommand;
        let prefixArgs = [...extraPrefixArgs];

        if (exeCommand === 'py -3') {
          exe = 'py';
          prefixArgs = ['-3', ...prefixArgs];
        }

        const args = [...prefixArgs, '-m', 'scanner', 'scan', absoluteTarget, '--format', 'json'];
        const fullCmd = `${exe} ${args.map((a) => (a.includes(' ') ? `"${a}"` : a)).join(' ')}`;

        if (this.outputChannel) {
          this.outputChannel.appendLine(`\n============================================================`);
          this.outputChannel.appendLine(`[Security Scanner] Spawning CLI Process`);
          this.outputChannel.appendLine(`  Command : ${fullCmd}`);
          this.outputChannel.appendLine(`  CWD     : ${cwd}`);
          this.outputChannel.appendLine(`  Target  : ${absoluteTarget}`);
          this.outputChannel.appendLine(`============================================================`);
        }

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

        child.on('error', (err: Error) => {
          if (onFallback) {
            onFallback(err);
          } else {
            const errMsg = `Failed to start scanner CLI "${exe}": ${err.message}`;
            if (this.outputChannel) {
              this.outputChannel.appendLine(`[ERROR] ${errMsg}`);
            }
            reject(new Error(errMsg));
          }
        });

        child.on('close', (code: number | null) => {
          if (this.outputChannel) {
            this.outputChannel.appendLine(`[Security Scanner] Exit Code: ${code}`);
            this.outputChannel.appendLine(`[Security Scanner] Received ${stdout.length} stdout and ${stderr.length} stderr characters.`);
            this.outputChannel.appendLine(`============================================================\n`);
          }

          if (code === 2) {
            reject(new Error('Scanner reported an incomplete scan (exit code 2). Run the same target from the CLI to view diagnostics.'));
            return;
          }

          // Parse stdout only; don't treat a non-zero exit as failure when stdout has valid JSON.
          try {
            const scanResult = parseScanResult(stdout);
            if (this.outputChannel) {
              this.outputChannel.appendLine(`[Security Scanner] Successfully parsed ${scanResult.findings.length} finding(s).`);
            }
            resolve(scanResult);
          } catch (parseErr) {
            const errMsg = `Scanner CLI output was not valid JSON (exit code ${code}).`;
            if (this.outputChannel) {
              this.outputChannel.appendLine(`[ERROR] ${errMsg}`);
            }
            reject(new Error(errMsg));
          }
        });
      };

      // Try configured pythonPath; if it fails with ENOENT on Windows, fallback to 'py -3'
      spawnProcess(configuredExe, [], (primaryErr) => {
        if (process.platform === 'win32' && (configuredExe === 'python' || configuredExe === 'python3')) {
          if (this.outputChannel) {
            this.outputChannel.appendLine(
              `[Security Scanner] Primary executable "${configuredExe}" failed (${primaryErr.message}). Trying fallback "py -3"...`
            );
          }
          spawnProcess('py -3', []);
        } else {
          const errMsg = `Failed to start scanner CLI "${configuredExe}": ${primaryErr.message}`;
          if (this.outputChannel) {
            this.outputChannel.appendLine(`[ERROR] ${errMsg}`);
          }
          reject(new Error(errMsg));
        }
      });
    });
  }
}
