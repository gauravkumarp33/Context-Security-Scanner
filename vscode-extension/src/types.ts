import * as vscode from 'vscode';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type Environment = 'production' | 'local-testing' | 'unknown';

export interface Finding {
  file: string;
  line: number;
  rule_id: string;
  severity: Severity;
  message: string;
  environment: Environment;
  confidence: number;
  recommendation: string;
}

export interface ScanResult {
  findings: Finding[];
  status?: string;
  errors?: string[];
}

export interface FindingsProvider {
  scan(workspaceFolder: vscode.WorkspaceFolder): Promise<ScanResult>;
}
