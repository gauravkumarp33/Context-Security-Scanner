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
}

/**
 * Production CLI provider executing the Python scanner binary.
 * Swappable with MockFindingsProvider. Uses child_process.spawn with executable and
 * arguments passed strictly as separate items, never as a shell string.
 */
export class CliFindingsProvider implements FindingsProvider {
  constructor(private readonly cliExecutable: string = 'code-security-scanner') {}

  scan(workspaceFolder: vscode.WorkspaceFolder): Promise<ScanResult> {
    return new Promise<ScanResult>((resolve, reject) => {
      const targetPath = workspaceFolder.uri.fsPath;
      const executable = this.cliExecutable || 'code-security-scanner';
      const args = ['scan', targetPath, '--format', 'json'];

      // Note: shell is explicitly false to prevent shell-injection vulnerabilities
      const child = child_process.spawn(executable, args, {
        cwd: targetPath,
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
        reject(
          new Error(
            `Failed to start scanner CLI "${executable}": ${err.message}`
          )
        );
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
    });
  }
}
