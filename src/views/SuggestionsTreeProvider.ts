import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from '../models/Finding';
import { Suggestion } from '../models/Suggestion';

interface SuggestionEntry {
  finding: Finding;
  suggestion: Suggestion;
}

export class SuggestionsTreeProvider implements vscode.TreeDataProvider<SuggestionTreeItem> {
  private readonly onDidChangeTreeDataEmitter = new vscode.EventEmitter<SuggestionTreeItem | undefined | null>();
  private items: SuggestionEntry[] = [];

  public readonly onDidChangeTreeData = this.onDidChangeTreeDataEmitter.event;

  public setFindings(findings: Finding[]): void {
    this.items = findings.flatMap((finding) => {
      const suggestions = finding.suggestions ?? [];
      return suggestions.map((suggestion) => ({ finding, suggestion }));
    });

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

    tooltip.appendMarkdown(`Linked finding: ${entry.finding.message}`);
    return tooltip;
  }
}
