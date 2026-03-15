import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from '../models/Finding';
import { RemediationAction } from '../models/Remediation';
import { FindingsStore } from '../services/FindingsStore';

export class SecureLensCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private readonly findingsStore: FindingsStore) {}

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.ProviderResult<vscode.CodeAction[]> {
    const secureLensDiagnostics = context.diagnostics.filter((diagnostic) => diagnostic.source === 'SecureLens');
    const actions: vscode.CodeAction[] = [];
    const seen = new Set<string>();

    for (const diagnostic of secureLensDiagnostics) {
      const findingId = this.resolveFindingId(diagnostic);
      if (!findingId) {
        continue;
      }

      const finding = this.findingsStore.getFindingById(findingId);
      if (!finding) {
        continue;
      }

      for (const suggestion of finding.suggestions ?? []) {
        const dedupeKey = `${finding.id}|${suggestion.id}|${suggestion.commandId ?? ''}|${suggestion.title}`;
        if (seen.has(dedupeKey)) {
          continue;
        }

        const action = this.toCodeAction(document, diagnostic, finding, suggestion);
        if (!action) {
          continue;
        }

        seen.add(dedupeKey);
        actions.push(action);
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
    if (!['javascript', 'typescript', 'javascriptreact', 'typescriptreact'].includes(document.languageId)) {
      return undefined;
    }

    const text = document.getText(diagnostic.range);
    const literalValue = this.extractLiteralValue(text);

    // If we cannot safely parse the current literal, skip the quick fix to avoid data loss.
    if (!literalValue) {
      return undefined;
    }

    const envName = this.deriveEnvName(text, finding);
    const fixed = text.replace(/([=:]\s*)(["'`])[^"'`]+(\2)/, `$1process.env.${envName}`);

    if (fixed === text) {
      return undefined;
    }

    const action = new vscode.CodeAction(suggestion.title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];

    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, diagnostic.range, fixed);
    this.ensureEnvFileContainsVar(edit, document.uri, envName, literalValue);

    action.edit = edit;
    action.isPreferred = suggestion.isPreferred ?? false;

    return action;
  }

  private ensureEnvFileContainsVar(
    edit: vscode.WorkspaceEdit,
    documentUri: vscode.Uri,
    envName: string,
    literalValue: string
  ): void {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(documentUri);
    if (!workspaceFolder) {
      return;
    }

    const envPath = path.join(workspaceFolder.uri.fsPath, '.env');
    const envUri = vscode.Uri.file(envPath);
    const envEntry = `${envName}=${this.toEnvValue(literalValue)}\n`;

    if (!fs.existsSync(envPath)) {
      edit.createFile(envUri, { ignoreIfExists: true });
      edit.insert(envUri, new vscode.Position(0, 0), envEntry);
      return;
    }

    const content = fs.readFileSync(envPath, 'utf8');
    const alreadyDefined = new RegExp(`^\\s*${this.escapeForRegex(envName)}\\s*=`, 'm').test(content);

    if (alreadyDefined) {
      return;
    }

    const lines = content.split('\n');
    const lastLineIndex = Math.max(lines.length - 1, 0);
    const lastChar = lines[lastLineIndex]?.length ?? 0;
    const prefix = content.endsWith('\n') ? '' : '\n';

    edit.insert(envUri, new vscode.Position(lastLineIndex, lastChar), `${prefix}${envEntry}`);
  }

  private extractLiteralValue(text: string): string | undefined {
    const literalMatch = text.match(/[=:]\s*(["'`])([^"'`]+)\1/);
    const value = literalMatch?.[2]?.trim();

    if (!value) {
      return undefined;
    }

    return value;
  }

  private toEnvValue(value: string): string {
    const needsQuotes = /\s|#|"|'/.test(value);
    if (!needsQuotes) {
      return value;
    }

    const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `"${escaped}"`;
  }

  private deriveEnvName(text: string, _finding: Finding): string {
    const variableMatch = text.match(/\b(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]/);
    const raw = variableMatch?.[1] ?? '';

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

    if (
      normalized.includes('KEY') ||
      normalized.includes('SECRET') ||
      normalized.includes('TOKEN') ||
      normalized.includes('PASSWORD')
    ) {
      return normalized;
    }

    return `${normalized}_VALUE`;
  }

  private resolveFindingId(diagnostic: vscode.Diagnostic): string | undefined {
    if (typeof diagnostic.code === 'string') {
      return diagnostic.code;
    }

    if (
      diagnostic.code &&
      typeof diagnostic.code === 'object' &&
      'value' in diagnostic.code &&
      typeof diagnostic.code.value === 'string'
    ) {
      return diagnostic.code.value;
    }

    return undefined;
  }

  private escapeForRegex(value: string): string {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}
