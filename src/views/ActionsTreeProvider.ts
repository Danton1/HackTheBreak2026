import * as vscode from 'vscode';

interface ActionDefinition {
  label: string;
  description: string;
  commandId: string;
}

const ACTIONS: ActionDefinition[] = [
  {
    label: 'Scan Current File',
    description: ' Run SecureLens on the active file',
    commandId: 'securelens.scanCurrentFile'
  },
  {
    label: 'Scan Workspace',
    description: ' Run SecureLens across workspace folders',
    commandId: 'securelens.scanWorkspace'
  }
];

export class ActionsTreeProvider implements vscode.TreeDataProvider<ActionTreeItem>, vscode.Disposable {
  private readonly onDidChangeTreeDataEmitter = new vscode.EventEmitter<ActionTreeItem | undefined | null>();

  public readonly onDidChangeTreeData = this.onDidChangeTreeDataEmitter.event;

  public getTreeItem(element: ActionTreeItem): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: ActionTreeItem): vscode.ProviderResult<ActionTreeItem[]> {
    if (element) {
      return [];
    }

    return ACTIONS.map((action) => new ActionTreeItem(action));
  }

  public dispose(): void {
    this.onDidChangeTreeDataEmitter.dispose();
  }
}

class ActionTreeItem extends vscode.TreeItem {
  constructor(action: ActionDefinition) {
    super(action.label, vscode.TreeItemCollapsibleState.None);

    this.description = action.description;
    this.iconPath = new vscode.ThemeIcon('play-circle');
    this.command = {
      command: action.commandId,
      title: action.label
    };
    this.contextValue = 'securelensAction';
  }
}
