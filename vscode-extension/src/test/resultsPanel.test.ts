import * as assert from 'assert';
import { Finding } from '../types';

const messages: ((message: unknown) => void)[] = [];
const opened: unknown[][] = [];
let created = 0;
let revealed = 0;
let disposed = 0;
const mockVscode = {
  ViewColumn: { Beside: 2 },
  window: {
    createWebviewPanel: () => {
      created++;
      let onDispose: (() => void) | undefined;
      return {
        webview: {
          html: '',
          onDidReceiveMessage: (listener: (message: unknown) => void) => { messages.push(listener); },
        },
        reveal: () => { revealed++; },
        dispose: () => { disposed++; onDispose?.(); },
        onDidDispose: (listener: () => void) => { onDispose = listener; },
      };
    },
  },
  commands: { executeCommand: (...args: unknown[]) => { opened.push(args); return Promise.resolve(); } },
};

const moduleWithLoad = require('module') as { _load: (request: string, parent: unknown, isMain: boolean) => unknown };
const originalLoad = moduleWithLoad._load;
moduleWithLoad._load = (request, parent, isMain) =>
  request === 'vscode' ? mockVscode : originalLoad(request, parent, isMain);
const { ResultsPanel, renderResultsHtml } = require('../resultsPanel') as typeof import('../resultsPanel');
moduleWithLoad._load = originalLoad;

const finding: Finding = {
  file: 'src/<unsafe>&.ts', line: 12, rule_id: 'RULE-1', severity: 'high',
  message: '<script>alert(1)</script>', environment: 'production', confidence: 0.8, recommendation: '',
};
const second: Finding = { ...finding, line: 20, severity: 'low', environment: 'local-testing' };

const html = renderResultsHtml([finding, second], 'C:\\workspace', 1200, 'test-nonce');
assert.ok(html.includes('2 issues in 1 file'));
assert.ok(html.includes('High 1'));
assert.ok(html.includes('Low 1'));
assert.ok(html.includes('production: 1'));
assert.ok(html.includes('local-testing: 1'));
assert.ok(html.includes('1.20s'));
assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
assert.ok(!html.includes('<script>alert(1)</script>'));
assert.ok(html.includes('data-open="0"'));
const absoluteHtml = renderResultsHtml([{ ...finding, file: 'C:\\workspace\\deploy\\docker-compose.yml' }], 'C:\\workspace', 100, 'test-nonce');
assert.ok(absoluteHtml.includes('deploy/docker-compose.yml'), 'absolute finding paths should display relative to the workspace');
assert.ok(!absoluteHtml.includes('C:\\workspace\\deploy'));

const panel = new ResultsPanel();
panel.show([finding, second], 'C:\\workspace', 1200);
panel.show([second], 'C:\\workspace', 500);
assert.strictEqual(created, 1, 'a subsequent scan should reuse the panel');
assert.strictEqual(revealed, 1);
messages[0]({ type: 'open', index: 0 });
messages[0]({ type: 'open', index: 4 });
assert.strictEqual(opened.length, 1, 'invalid finding indexes should be ignored');
assert.strictEqual(opened[0][0], 'security-scanner.openFinding');
assert.strictEqual(opened[0][1], second, 'navigation should use the latest scan');
messages[0]({ type: 'close' });
assert.strictEqual(disposed, 1);
panel.show([finding], 'C:\\workspace', 300);
assert.strictEqual(created, 2, 'a closed panel should open again after the next scan');
panel.dispose();
console.log('Results panel tests passed.');
