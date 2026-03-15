import * as vscode from 'vscode';
import { FindingsStore } from '../services/FindingsStore';
import { Finding } from '../models/Finding';
import { RemediationAction } from '../models/Remediation';

export class SecureLensCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private readonly findingsStore: FindingsStore) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.ProviderResult<vscode.CodeAction[]> {
    const secureLensDiagnostics = context.diagnostics.filter(
      (diagnostic) => diagnostic.source === 'SecureLens'
    );

    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of secureLensDiagnostics) {
      let findingId: string | undefined;

      if (typeof diagnostic.code === 'string') {
        findingId = diagnostic.code;
      } else if (
        diagnostic.code &&
        typeof diagnostic.code === 'object' &&
        'value' in diagnostic.code &&
        typeof diagnostic.code.value === 'string'
      ) {
        findingId = diagnostic.code.value;
      }

      if (!findingId) {
        continue;
      }

      const finding = this.findingsStore.getFindingById(findingId);
      if (!finding) {
        continue;
      }

      for (const suggestion of finding.suggestions ?? []) {
        const action = this.toCodeAction(document, diagnostic, finding, suggestion);
        if (action) {
          actions.push(action);
        }
      }
    }

    return actions;
  }

  private toCodeAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    finding: Finding,
    suggestion: RemediationAction
  ): vscode.CodeAction | undefined {
    if (suggestion.kind === 'quickfix') {
      if (suggestion.commandId === 'securelens.quickfix.convertInnerHtml') {
        return this.createInnerHtmlFix(document, diagnostic, suggestion);
      }

      if (suggestion.commandId === 'securelens.quickfix.replaceWithEnv') {
        return this.createReplaceWithEnvFix(document, diagnostic, finding, suggestion);
      }
    }

    if (suggestion.commandId === 'securelens.quickfix.showEvalGuidance') {
      const action = new vscode.CodeAction(suggestion.title, vscode.CodeActionKind.QuickFix);
      action.diagnostics = [diagnostic];
      action.command = {
        command: suggestion.commandId,
        title: suggestion.title,
        arguments: [finding]
      };
      action.isPreferred = suggestion.isPreferred ?? false;
      return action;
    }

    return undefined;
  }

  private createInnerHtmlFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    suggestion: RemediationAction
  ): vscode.CodeAction | undefined {
    const text = document.getText(diagnostic.range);

    if (!text.includes('innerHTML')) {
      return undefined;
    }

    const fixed = text.replace(/\.innerHTML\b/g, '.textContent');
    if (fixed === text) {
      return undefined;
    }

    const action = new vscode.CodeAction(suggestion.title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.edit = new vscode.WorkspaceEdit();
    action.edit.replace(document.uri, diagnostic.range, fixed);
    action.isPreferred = suggestion.isPreferred ?? false;

    return action;
  }

  private createReplaceWithEnvFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    finding: Finding,
    suggestion: RemediationAction
  ): vscode.CodeAction | undefined {
    const text = document.getText(diagnostic.range);
    const envName = this.deriveEnvName(text, finding);

    // Replace quoted literal after = or :
    const fixed = text.replace(
      /([=:]\s*)(["'`])[^"'`]+(\2)/,
      `$1process.env.${envName}`
    );

    if (fixed === text) {
      return undefined;
    }

    const action = new vscode.CodeAction(suggestion.title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.edit = new vscode.WorkspaceEdit();
    action.edit.replace(document.uri, diagnostic.range, fixed);
    action.isPreferred = suggestion.isPreferred ?? false;

    return action;
  }

  private deriveEnvName(text: string, finding: Finding): string {
    const variableMatch = text.match(/\b(const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]/);
    const raw = variableMatch?.[2] ?? '';

    if (!raw) {
      return 'SECRET_VALUE';
    }

    const normalized = raw
      .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
      .replace(/[^A-Za-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .toUpperCase();

    if (!normalized) {
      return 'SECRET_VALUE';
    }

    if (normalized.includes('KEY') || normalized.includes('SECRET') || normalized.includes('TOKEN') || normalized.includes('PASSWORD')) {
      return normalized;
    }

    return `${normalized}_VALUE`;
  }
}
