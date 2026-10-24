import * as vscode from 'vscode';
import { Finding, Severity } from './types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export class FindingTreeItem extends vscode.TreeItem {
  constructor(public readonly finding: Finding, public readonly scanRoot?: string) {
    super(finding.rule_id, vscode.TreeItemCollapsibleState.None);

    const confidencePct = Math.round((finding.confidence ?? 0) * 100);
    const env = finding.environment || 'unknown';
    this.description = `${finding.file}:${finding.line} [${env} (${confidencePct}%)]`;

    const md = new vscode.MarkdownString();
    md.isTrusted = true;
    md.appendMarkdown(`**[${finding.rule_id}] ${finding.severity.toUpperCase()}**\n\n`);
    md.appendMarkdown(`${finding.message}\n\n`);
    md.appendMarkdown(`---\n\n`);
    md.appendMarkdown(`- **Environment:** \`${env}\`\n`);
    md.appendMarkdown(`- **Confidence:** ${confidencePct}%\n`);
    md.appendMarkdown(`- **Recommendation:** ${finding.recommendation || 'None'}\n`);
    md.appendMarkdown(`- **Location:** \`${finding.file}:${finding.line}\`\n`);
    if (finding.evidence && finding.evidence.length > 0) {
      md.appendMarkdown(`- **Evidence:**\n`);
      for (const ev of finding.evidence) {
        md.appendMarkdown(`  - ${ev}\n`);
      }
    } else {
      md.appendMarkdown(`- **Evidence:** None\n`);
    }
    md.appendMarkdown(`- **Source:** Security Scanner\n`);
    this.tooltip = md;

    switch (finding.severity) {
      case 'critical':
        this.iconPath = new vscode.ThemeIcon(
          'error',
          new vscode.ThemeColor('errorForeground')
        );
        break;
      case 'high':
        this.iconPath = new vscode.ThemeIcon(
          'warning',
          new vscode.ThemeColor('editorWarning.foreground')
        );
        break;
      case 'medium':
        this.iconPath = new vscode.ThemeIcon(
          'info',
          new vscode.ThemeColor('editorInfo.foreground')
        );
        break;
      case 'low':
      default:
        this.iconPath = new vscode.ThemeIcon(
          'circle-outline',
          new vscode.ThemeColor('descriptionForeground')
        );
        break;
    }

    this.command = {
      command: 'security-scanner.openFinding',
      title: 'Open Finding',
      arguments: [finding, scanRoot],
    };
  }
}

export class SeverityGroupTreeItem extends vscode.TreeItem {
  constructor(
    public readonly severity: Severity,
    public readonly count: number,
    public readonly findings: Finding[]
  ) {
    const title = severity.charAt(0).toUpperCase() + severity.slice(1);
    super(`${title} (${count})`, vscode.TreeItemCollapsibleState.Expanded);

    this.contextValue = 'severityGroup';
    switch (severity) {
      case 'critical':
        this.iconPath = new vscode.ThemeIcon(
          'flame',
          new vscode.ThemeColor('errorForeground')
        );
        break;
      case 'high':
        this.iconPath = new vscode.ThemeIcon(
          'alert',
          new vscode.ThemeColor('editorWarning.foreground')
        );
        break;
      case 'medium':
        this.iconPath = new vscode.ThemeIcon(
          'bell',
          new vscode.ThemeColor('editorInfo.foreground')
        );
        break;
      case 'low':
        this.iconPath = new vscode.ThemeIcon(
          'info',
          new vscode.ThemeColor('descriptionForeground')
        );
        break;
    }
  }
}

export type SecurityTreeItem = SeverityGroupTreeItem | FindingTreeItem;

export class SecurityFindingsTreeProvider
  implements vscode.TreeDataProvider<SecurityTreeItem>
{
  private _onDidChangeTreeData: vscode.EventEmitter<
    SecurityTreeItem | undefined | null | void
  > = new vscode.EventEmitter<SecurityTreeItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<
    SecurityTreeItem | undefined | null | void
  > = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];
  private scanRoot?: string;

  setFindings(findings: Finding[], scanRoot?: string): void {
    this.findings = findings;
    this.scanRoot = scanRoot;
    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this.findings = [];
    this.scanRoot = undefined;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: SecurityTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: SecurityTreeItem): Thenable<SecurityTreeItem[]> {
    if (!element) {
      // Group findings by severity
      const groups: SeverityGroupTreeItem[] = [];
      for (const sev of SEVERITY_ORDER) {
        const matches = this.findings.filter((f) => f.severity === sev);
        if (matches.length > 0) {
          groups.push(new SeverityGroupTreeItem(sev, matches.length, matches));
        }
      }
      return Promise.resolve(groups);
    }

    if (element instanceof SeverityGroupTreeItem) {
      const items = element.findings.map((f) => new FindingTreeItem(f, this.scanRoot));
      return Promise.resolve(items);
    }

    return Promise.resolve([]);
  }
}
