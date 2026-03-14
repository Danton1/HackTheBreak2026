import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from '../models/Finding';

export class FindingsTreeProvider implements vscode.TreeDataProvider<FindingTreeItem> {
  private readonly onDidChangeTreeDataEmitter = new vscode.EventEmitter<FindingTreeItem | undefined | null>();
  private findings: Finding[] = [];

  public readonly onDidChangeTreeData = this.onDidChangeTreeDataEmitter.event;

  public setFindings(findings: Finding[]): void {
    this.findings = [...findings].sort((left, right) => {
      if (left.filePath !== right.filePath) {
        return left.filePath.localeCompare(right.filePath);
      }

      return left.startLine - right.startLine;
    });

    this.onDidChangeTreeDataEmitter.fire(undefined);
  }

  public getTreeItem(element: FindingTreeItem): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: FindingTreeItem): vscode.ProviderResult<FindingTreeItem[]> {
    if (element) {
      return [];
    }

    return this.findings.map((finding) => new FindingTreeItem(finding));
  }

  public dispose(): void {
    this.onDidChangeTreeDataEmitter.dispose();
  }
}

export class FindingTreeItem extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    const fileName = path.basename(finding.filePath);

    super(finding.message, vscode.TreeItemCollapsibleState.None);

    this.description = `${finding.severity} | ${fileName}:${finding.startLine}`;
    this.tooltip = this.buildTooltip(finding);
    this.command = {
      command: 'securelens.openFinding',
      title: 'Open Finding',
      arguments: [finding]
    };
    this.contextValue = 'securelensFinding';
  }

  private buildTooltip(finding: Finding): string {
    const description = finding.helpText ? `\n${finding.helpText}` : '';
    return `${finding.ruleId}\n${finding.filePath}:${finding.startLine}${description}`;
  }
}

