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

/**
 * Production CLI provider executing the Python scanner binary or module.
 * Swappable with MockFindingsProvider. Uses child_process.spawn with executable and
 * arguments passed strictly as separate items, never as a shell string.
 */
export class CliFindingsProvider implements FindingsProvider {
  constructor(private readonly cliExecutable: string = 'code-security-scanner') {}

  scan(workspaceFolder: vscode.WorkspaceFolder): Promise<ScanResult> {
    return this.runCliScan(workspaceFolder.uri.fsPath, workspaceFolder.uri.fsPath);
  }

  scanFile(fileUri: vscode.Uri, workspaceFolder?: vscode.WorkspaceFolder): Promise<ScanResult> {
    const cwd = workspaceFolder ? workspaceFolder.uri.fsPath : path.dirname(fileUri.fsPath);
    return this.runCliScan(fileUri.fsPath, cwd);
  }

  private runCliScan(targetPath: string, cwd: string): Promise<ScanResult> {
    return new Promise<ScanResult>((resolve, reject) => {
      const configuredExe = this.cliExecutable || 'code-security-scanner';

      const spawnProcess = (exe: string, args: string[], onFallback?: (err: Error) => void) => {
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
            reject(
              new Error(
                `Failed to start scanner CLI "${exe}": ${err.message}`
              )
            );
          }
        });

        child.on('close', (code: number | null) => {
          // Exit Code Contract:
          // 0 = Clean / Success
          // 1 = Blocking findings detected (scan still succeeded)
          // 2 = Scanner Error
          if (code === 0 || code === 1) {
            try {
              const scanResult = parseScanResult(stdout);
              resolve(scanResult);
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              reject(
                new Error(
                  `Failed to parse scanner output (exit code ${code}): ${msg}\nOutput: ${stdout}`
                )
              );
            }
          } else {
            reject(
              new Error(
                `Scanner CLI failed with exit code ${code}.\n${stderr || stdout}`
              )
            );
          }
        });
      };

      // Try configured executable; if it fails with ENOENT and is the default, try python -m scanner fallback
      const primaryArgs = ['scan', targetPath, '--format', 'json'];
      spawnProcess(configuredExe, primaryArgs, (primaryErr) => {
        if (configuredExe === 'code-security-scanner') {
          // Fallback to python -m scanner
          const fallbackExe = process.platform === 'win32' ? 'python' : 'python3';
          const fallbackArgs = ['-m', 'scanner', 'scan', targetPath, '--format', 'json'];
          spawnProcess(fallbackExe, fallbackArgs);
        } else {
          reject(
            new Error(
              `Failed to start scanner CLI "${configuredExe}": ${primaryErr.message}`
            )
          );
        }
      });
    });
  }
}
