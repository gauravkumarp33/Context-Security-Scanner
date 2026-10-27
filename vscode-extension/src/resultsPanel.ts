import * as crypto from 'crypto';
import * as path from 'path';
import * as vscode from 'vscode';
import { Finding, Severity } from './types';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[character]!));
}

function displayPath(file: string, scanRoot: string): string {
  const relative = path.isAbsolute(file) ? path.relative(scanRoot, file) : file;
  return relative.replace(/\\/g, '/');
}

export function renderResultsHtml(findings: Finding[], scanRoot: string, durationMs: number, nonce: string): string {
  const counts = new Map(SEVERITIES.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length]));
  const environments = new Map<string, number>();
  const files = new Map<string, { finding: Finding; index: number }[]>();
  findings.forEach((finding, index) => {
    environments.set(finding.environment, (environments.get(finding.environment) || 0) + 1);
    const file = displayPath(finding.file, scanRoot);
    const group = files.get(file) || [];
    group.push({ finding, index });
    files.set(file, group);
  });

  const badges = SEVERITIES.map((severity) =>
    `<span class="badge ${severity}">${severity[0].toUpperCase() + severity.slice(1)} ${counts.get(severity)}</span>`
  ).join('');
  const environmentStats = [...environments.entries()]
    .map(([environment, count]) => `${escapeHtml(environment)}: ${count}`)
    .join(' · ');
  const groups = [...files.entries()].map(([file, items], groupIndex) => {
    const findingsHtml = items.map(({ finding, index }) => `
      <button class="finding" type="button" data-open="${index}" data-env="${escapeHtml(finding.environment)}" data-severity="${finding.severity}">
        <span class="finding-line">Line ${finding.line}</span>
        <span class="finding-main"><strong>${escapeHtml(finding.rule_id)}</strong><span>${escapeHtml(finding.message)}</span></span>
        <span class="badge ${finding.severity}">${finding.severity}</span>
        <span class="environment">${escapeHtml(finding.environment)}</span>
      </button>`).join('');
    return `<section class="file-group">
      <div class="file-header">
        <button class="file-open" type="button" data-open="${items[0].index}" title="Open first finding in file">${escapeHtml(file)} <span class="count">${items.length}</span></button>
        <button class="toggle" type="button" data-toggle="${groupIndex}" aria-expanded="true" aria-label="Collapse findings in ${escapeHtml(file)}">▾</button>
      </div>
      <div class="findings" id="group-${groupIndex}">${findingsHtml}</div>
    </section>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
<title>Security Scan Results</title>
<style nonce="${nonce}">
  :root { color-scheme: light dark; }
  body { margin: 0; padding: 20px; background: var(--vscode-editor-background); color: var(--vscode-foreground); font-family: var(--vscode-font-family); }
  button { font: inherit; cursor: pointer; }
  button:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 2px; }
  .top { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  h1 { font-size: 1.4rem; margin: 0; }
  h2 { font-size: 1rem; margin: 0 0 12px; }
  .close, .filter, .toggle { border: 1px solid var(--vscode-panel-border); border-radius: 5px; padding: 5px 10px; color: var(--vscode-foreground); background: var(--vscode-button-secondaryBackground); }
  .close:hover, .filter:hover, .toggle:hover { background: var(--vscode-button-secondaryHoverBackground); }
  .summary { margin: 18px 0; padding: 16px; border: 1px solid var(--vscode-panel-border); border-radius: 8px; background: var(--vscode-editorWidget-background); }
  .total { font-size: 1.2rem; font-weight: 700; margin-bottom: 10px; }
  .badges, .filters { display: flex; flex-wrap: wrap; gap: 8px; }
  .badge, .count { display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: .8rem; font-weight: 600; white-space: nowrap; }
  .critical { color: var(--vscode-errorForeground); background: var(--vscode-inputValidation-errorBackground); }
  .high { color: var(--vscode-editorWarning-foreground); background: var(--vscode-inputValidation-warningBackground); }
  .medium { color: var(--vscode-editorInfo-foreground); background: var(--vscode-editorWidget-background); }
  .low { color: var(--vscode-descriptionForeground); background: var(--vscode-editorWidget-background); }
  .meta { margin-top: 12px; color: var(--vscode-descriptionForeground); }
  .filters { margin-bottom: 18px; }
  .filter[aria-pressed="true"] { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border-color: var(--vscode-button-background); }
  .file-group { border: 1px solid var(--vscode-panel-border); border-radius: 7px; margin-bottom: 10px; overflow: hidden; }
  .file-header { display: flex; align-items: stretch; background: var(--vscode-sideBar-background); }
  .file-open { flex: 1; min-width: 0; text-align: left; overflow-wrap: anywhere; border: 0; padding: 10px 12px; color: var(--vscode-textLink-foreground); background: transparent; }
  .file-open:hover, .finding:hover { background: var(--vscode-list-hoverBackground); }
  .count { margin-left: 8px; color: var(--vscode-foreground); background: var(--vscode-badge-background); }
  .toggle { border: 0; border-left: 1px solid var(--vscode-panel-border); border-radius: 0; }
  .finding { display: flex; align-items: baseline; flex-wrap: wrap; gap: 8px; width: 100%; border: 0; border-top: 1px solid var(--vscode-panel-border); padding: 10px 12px; text-align: left; color: var(--vscode-foreground); background: transparent; }
  .finding-main { flex: 1; min-width: 180px; display: flex; flex-direction: column; gap: 4px; }
  .finding-line, .environment { color: var(--vscode-descriptionForeground); font-size: .85rem; }
  [hidden] { display: none !important; }
</style></head><body>
  <header class="top"><h1>Security Scan Results</h1><button class="close" id="close" type="button">✖ Close</button></header>
  <div class="summary"><div class="total">${findings.length} issue${findings.length === 1 ? '' : 's'} in ${files.size} file${files.size === 1 ? '' : 's'}</div>
    <div class="badges">${badges}</div><div class="meta">Scan duration: ${(durationMs / 1000).toFixed(2)}s · ${environmentStats}</div></div>
  <div class="filters" aria-label="Filter findings">
    <button class="filter" type="button" data-filter="all" aria-pressed="true">All</button>
    <button class="filter" type="button" data-filter="production" aria-pressed="false">Production Only</button>
    <button class="filter" type="button" data-filter="high" aria-pressed="false">High/Critical Only</button>
  </div>
  <main><h2>Files</h2>${groups}</main>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    document.getElementById('close').addEventListener('click', () => vscode.postMessage({ type: 'close' }));
    document.querySelectorAll('[data-open]').forEach((button) => button.addEventListener('click', () =>
      vscode.postMessage({ type: 'open', index: Number(button.dataset.open) })));
    document.querySelectorAll('[data-toggle]').forEach((button) => button.addEventListener('click', () => {
      const contents = document.getElementById('group-' + button.dataset.toggle);
      contents.hidden = !contents.hidden;
      button.setAttribute('aria-expanded', String(!contents.hidden));
      button.textContent = contents.hidden ? '▸' : '▾';
    }));
    document.querySelectorAll('[data-filter]').forEach((button) => button.addEventListener('click', () => {
      const filter = button.dataset.filter;
      document.querySelectorAll('[data-filter]').forEach((pill) => pill.setAttribute('aria-pressed', String(pill === button)));
      document.querySelectorAll('.file-group').forEach((group) => {
        let visible = 0;
        group.querySelectorAll('.finding').forEach((finding) => {
          const show = filter === 'all' || (filter === 'production' && finding.dataset.env === 'production') ||
            (filter === 'high' && ['high', 'critical'].includes(finding.dataset.severity));
          finding.hidden = !show;
          if (show) visible++;
        });
        group.hidden = visible === 0;
        group.querySelector('.count').textContent = String(visible);
        if (visible > 0) group.querySelector('.file-open').dataset.open = group.querySelector('.finding:not([hidden])').dataset.open;
      });
    }));
  </script>
</body></html>`;
}

export class ResultsPanel {
  private panel: vscode.WebviewPanel | undefined;
  private findings: Finding[] = [];
  private scanRoot = '';

  show(findings: Finding[], scanRoot: string, durationMs: number): void {
    this.findings = [...findings];
    this.scanRoot = scanRoot;
    if (this.panel) {
      this.panel.reveal(vscode.ViewColumn.Beside);
    } else {
      const panel = vscode.window.createWebviewPanel('securityScanner.results', 'Security Scan Results', vscode.ViewColumn.Beside, {
        enableScripts: true,
      });
      this.panel = panel;
      panel.onDidDispose(() => { if (this.panel === panel) this.panel = undefined; });
      panel.webview.onDidReceiveMessage((message: unknown) => {
        if (!message || typeof message !== 'object') return;
        const request = message as { type?: unknown; index?: unknown };
        if (request.type === 'close') {
          panel.dispose();
        } else if (request.type === 'open' && Number.isInteger(request.index) &&
          (request.index as number) >= 0 && (request.index as number) < this.findings.length) {
          void vscode.commands.executeCommand('security-scanner.openFinding', this.findings[request.index as number], this.scanRoot);
        }
      });
    }
    const nonce = crypto.randomBytes(16).toString('base64');
    this.panel.webview.html = renderResultsHtml(this.findings, this.scanRoot, durationMs, nonce);
  }

  dispose(): void {
    this.panel?.dispose();
    this.panel = undefined;
  }
}
