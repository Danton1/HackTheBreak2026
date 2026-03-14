import * as vscode from 'vscode';
import { Suggestion } from './Suggestion';

export type FindingSeverity = 'ERROR' | 'WARNING' | 'INFO';

export interface Finding {
  id: string;
  ruleId: string;
  message: string;
  severity: FindingSeverity;
  filePath: string;
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
  snippet?: string;
  helpText?: string;
  suggestions?: Suggestion[];
}

export function findingToRange(finding: Finding): vscode.Range {
  const startLine = Math.max(finding.startLine - 1, 0);
  const startCol = Math.max(finding.startCol - 1, 0);
  const endLine = Math.max(finding.endLine - 1, startLine);
  const endCol = Math.max(finding.endCol - 1, startCol + 1);

  return new vscode.Range(
    new vscode.Position(startLine, startCol),
    new vscode.Position(endLine, endCol)
  );
}
