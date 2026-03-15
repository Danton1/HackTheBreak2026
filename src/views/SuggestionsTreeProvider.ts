import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from '../models/Finding';
import { RemediationAction } from '../models/Remediation';

interface SuggestionEntry {
  finding: Finding;
  suggestion: RemediationAction;
}

export class SuggestionsTreeProvider implements vscode.TreeDataProvider<SuggestionTreeItem> {
  private readonly onDidChangeTreeDataEmitter = new vscode.EventEmitter<SuggestionTreeItem | undefined | null>();
  private items: SuggestionEntry[] = [];

  public readonly onDidChangeTreeData = this.onDidChangeTreeDataEmitter.event;

  public setFindings(findings: Finding[]): void {
    const seen = new Set<string>();
    const nextItems: SuggestionEntry[] = [];

    for (const finding of findings) {
      for (const suggestion of finding.suggestions ?? []) {
        const key = this.makeSuggestionKey(finding, suggestion);
        if (seen.has(key)) {
          continue;
        }

        seen.add(key);
        nextItems.push({ finding, suggestion });
      }
    }

    this.items = nextItems;
    this.onDidChangeTreeDataEmitter.fire(undefined);
  }

  public getTreeItem(element: SuggestionTreeItem): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: SuggestionTreeItem): vscode.ProviderResult<SuggestionTreeItem[]> {
    if (element) {
      return [];
    }

    if (this.items.length === 0) {
      return [new SuggestionTreeItem()];
    }

    return this.items.map((entry) => new SuggestionTreeItem(entry));
  }

  public dispose(): void {
    this.onDidChangeTreeDataEmitter.dispose();
  }

  private makeSuggestionKey(finding: Finding, suggestion: RemediationAction): string {
    const findingKey = this.makeFindingScopeKey(finding);
    const rangeKey = `${finding.startLine}:${finding.startCol}-${finding.endLine}:${finding.endCol}`;
    const commandKey = suggestion.commandId ?? '';
    const titleKey = this.normalizeSuggestionText(suggestion.title);
    const detailKey = this.normalizeSuggestionText(suggestion.detail ?? '');

    return `${findingKey}|${rangeKey}|${suggestion.kind}|${commandKey}|${titleKey}|${detailKey}`;
  }

  private makeFindingScopeKey(finding: Finding): string {
    const categoryKey = finding.category && finding.category !== 'generic-security-warning' ? finding.category : finding.ruleId;
    return `${finding.filePath}|${categoryKey}`;
  }

  private normalizeSuggestionText(value: string): string {
    return value.trim().toLowerCase();
  }
}

class SuggestionTreeItem extends vscode.TreeItem {
  constructor(entry?: SuggestionEntry) {
    if (!entry) {
      super('No suggestions for current findings', vscode.TreeItemCollapsibleState.None);
      this.description = 'Run a scan to populate this section';
      this.contextValue = 'securelensSuggestionPlaceholder';
      return;
    }

    super(entry.suggestion.title, vscode.TreeItemCollapsibleState.None);

    const fileName = path.basename(entry.finding.filePath);
    this.description = `${fileName}:${entry.finding.startLine}`;
    this.tooltip = this.buildTooltip(entry);
    this.iconPath = new vscode.ThemeIcon('lightbulb');
    this.command = {
      command: 'securelens.openFinding',
      title: 'Open Finding',
      arguments: [entry.finding]
    };
    this.contextValue = 'securelensSuggestion';
  }

  private buildTooltip(entry: SuggestionEntry): vscode.MarkdownString {
    const tooltip = new vscode.MarkdownString(undefined, true);
    tooltip.isTrusted = false;

    tooltip.appendMarkdown(`**${entry.suggestion.title}**\n\n`);
    if (entry.suggestion.detail) {
      tooltip.appendMarkdown(`${entry.suggestion.detail}\n\n`);
    }

    if (entry.finding.detailedSolution) {
      tooltip.appendMarkdown(`**What to do next**\n${entry.finding.detailedSolution}\n\n`);
    }

    tooltip.appendMarkdown(`Linked finding: ${entry.finding.message}`);
    return tooltip;
  }
}
