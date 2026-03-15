import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from '../models/Finding';
import { RemediationAction } from '../models/Remediation';
import { FindingsStore } from '../services/FindingsStore';

interface EnvResolution {
  resolvedName: string;
  shouldAppend: boolean;
}

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
        const dedupeKey = this.makeActionDedupeKey(finding, diagnostic, suggestion);
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

  private makeActionDedupeKey(
    finding: Finding,
    diagnostic: vscode.Diagnostic,
    suggestion: RemediationAction
  ): string {
    const findingKey = this.makeFindingScopeKey(finding);
    const rangeKey = this.rangeToKey(diagnostic.range);
    const commandKey = suggestion.commandId ?? '';
    const fallbackTitleKey = commandKey ? '' : this.normalizeSuggestionText(suggestion.title);
    const fallbackDetailKey = commandKey ? '' : this.normalizeSuggestionText(suggestion.detail ?? '');

    return `${findingKey}|${rangeKey}|${suggestion.kind}|${commandKey}|${fallbackTitleKey}|${fallbackDetailKey}`;
  }

  private makeFindingScopeKey(finding: Finding): string {
    const categoryKey = finding.category && finding.category !== 'generic-security-warning' ? finding.category : finding.ruleId;
    return `${finding.filePath}|${categoryKey}`;
  }

  private rangeToKey(range: vscode.Range): string {
    return `${range.start.line}:${range.start.character}-${range.end.line}:${range.end.character}`;
  }

  private normalizeSuggestionText(value: string): string {
    return value.trim().toLowerCase();
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
    action.command = this.createPostFixRescanCommand();
    action.isPreferred = suggestion.isPreferred ?? false;

    return action;
  }

  private ensureGitignoreContainsEnv(edit: vscode.WorkspaceEdit, workspaceRoot: string): void {
    const gitignorePath = path.join(workspaceRoot, '.gitignore');
    const gitignoreUri = vscode.Uri.file(gitignorePath);
    const envEntry = '.env';

    if (!fs.existsSync(gitignorePath)) {
      edit.createFile(gitignoreUri, { ignoreIfExists: true });
      edit.insert(gitignoreUri, new vscode.Position(0, 0), `${envEntry}\n`);
      return;
    }

    const content = fs.readFileSync(gitignorePath, 'utf8');
    if (this.gitignoreContainsEntry(content, envEntry)) {
      return;
    }

    const lines = content.split('\n');
    const lastLineIndex = Math.max(lines.length - 1, 0);
    const lastChar = lines[lastLineIndex]?.length ?? 0;
    const prefix = content.endsWith('\n') ? '' : '\n';

    edit.insert(gitignoreUri, new vscode.Position(lastLineIndex, lastChar), `${prefix}${envEntry}\n`);
  }

  private gitignoreContainsEntry(content: string, entry: string): boolean {
    const lines = content.split(/\r?\n/);

    return lines.some((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        return false;
      }

      return trimmed === entry;
    });
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

    const assignmentContext = this.extractAssignmentContext(document, diagnostic, finding);
    if (!assignmentContext) {
      return undefined;
    }

    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!workspaceFolder) {
      return undefined;
    }

    const envPath = path.join(workspaceFolder.uri.fsPath, '.env');
    const envMap = this.readEnvMap(envPath);
    const baseName = this.deriveEnvName(assignmentContext.identifier);
    const envResolution = this.resolveEnvName(baseName, assignmentContext.literalValue, envMap);

    const fixed = assignmentContext.text.replace(
      /([=:]\s*)(["'`])[^"'`]+(\2)/,
      `$1process.env.${envResolution.resolvedName}`
    );

    if (fixed === assignmentContext.text) {
      return undefined;
    }

    const action = new vscode.CodeAction(suggestion.title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];

    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, assignmentContext.range, fixed);

    if (envResolution.shouldAppend) {
      this.appendEnvValue(edit, envPath, envResolution.resolvedName, assignmentContext.literalValue);
    }

    this.ensureGitignoreContainsEnv(edit, workspaceFolder.uri.fsPath);

    action.edit = edit;
    action.command = this.createPostFixRescanCommand();
    action.isPreferred = suggestion.isPreferred ?? false;

    return action;
  }

  private shouldRerunScanOnQuickFix(): boolean {
    const config = vscode.workspace.getConfiguration('securelens');
    return config.get<boolean>('rerunScanOnQuickFix', true);
  }

  private createPostFixRescanCommand(): vscode.Command | undefined {
    if (!this.shouldRerunScanOnQuickFix()) {
      return undefined;
    }

    return {
      title: 'Rescan current file',
      command: 'securelens.scanCurrentFile'
    };
  }

  private extractAssignmentContext(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    finding: Finding
  ): { identifier: string; literalValue: string; text: string; range: vscode.Range } | undefined {
    const line = document.lineAt(diagnostic.range.start.line);
    const lineText = line.text;
    const assignmentMatch = lineText.match(/\b(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(["'`])([^"'`]+)\2/);

    if (assignmentMatch) {
      const startChar = assignmentMatch.index ?? 0;
      const endChar = startChar + assignmentMatch[0].length;

      return {
        identifier: assignmentMatch[1],
        literalValue: assignmentMatch[3],
        text: assignmentMatch[0],
        range: new vscode.Range(
          new vscode.Position(diagnostic.range.start.line, startChar),
          new vscode.Position(diagnostic.range.start.line, endChar)
        )
      };
    }

    const text = document.getText(diagnostic.range);
    const fallbackMatch = text.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(["'`])([^"'`]+)\2/);

    if (!fallbackMatch) {
      return undefined;
    }

    return {
      identifier: fallbackMatch[1] || this.deriveIdentifierFromFinding(finding),
      literalValue: fallbackMatch[3],
      text,
      range: diagnostic.range
    };
  }

  private deriveIdentifierFromFinding(finding: Finding): string {
    const snippet = finding.snippet ?? '';
    const match = snippet.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]/);
    return match?.[1] ?? 'SECRET_VALUE';
  }

  private appendEnvValue(
    edit: vscode.WorkspaceEdit,
    envPath: string,
    envName: string,
    literalValue: string
  ): void {
    const envUri = vscode.Uri.file(envPath);
    const envEntry = `${envName}=${this.toEnvValue(literalValue)}\n`;

    if (!fs.existsSync(envPath)) {
      edit.createFile(envUri, { ignoreIfExists: true });
      edit.insert(envUri, new vscode.Position(0, 0), envEntry);
      return;
    }

    const content = fs.readFileSync(envPath, 'utf8');
    const lines = content.split('\n');
    const lastLineIndex = Math.max(lines.length - 1, 0);
    const lastChar = lines[lastLineIndex]?.length ?? 0;
    const prefix = content.endsWith('\n') ? '' : '\n';

    edit.insert(envUri, new vscode.Position(lastLineIndex, lastChar), `${prefix}${envEntry}`);
  }

  private readEnvMap(envPath: string): Map<string, string> {
    const map = new Map<string, string>();

    if (!fs.existsSync(envPath)) {
      return map;
    }

    const content = fs.readFileSync(envPath, 'utf8');
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      const eqIndex = trimmed.indexOf('=');
      if (eqIndex <= 0) {
        continue;
      }

      const key = trimmed.slice(0, eqIndex).trim();
      const value = trimmed.slice(eqIndex + 1).trim();
      map.set(key, value);
    }

    return map;
  }

  private resolveEnvName(baseName: string, literalValue: string, envMap: Map<string, string>): EnvResolution {
    const normalizedNewValue = this.normalizeEnvValue(literalValue);

    const existingBase = envMap.get(baseName);
    if (!existingBase) {
      return { resolvedName: baseName, shouldAppend: true };
    }

    if (this.normalizeEnvValue(existingBase) === normalizedNewValue) {
      return { resolvedName: baseName, shouldAppend: false };
    }

    let suffix = 1;
    while (suffix < 1000) {
      const candidate = `${baseName}_${suffix}`;
      const existingCandidate = envMap.get(candidate);

      if (!existingCandidate) {
        return { resolvedName: candidate, shouldAppend: true };
      }

      if (this.normalizeEnvValue(existingCandidate) === normalizedNewValue) {
        return { resolvedName: candidate, shouldAppend: false };
      }

      suffix += 1;
    }

    return { resolvedName: `${baseName}_1`, shouldAppend: true };
  }

  private normalizeEnvValue(value: string): string {
    const trimmed = value.trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
      return trimmed.slice(1, -1);
    }

    return trimmed;
  }

  private toEnvValue(value: string): string {
    const needsQuotes = /\s|#|"|'/.test(value);
    if (!needsQuotes) {
      return value;
    }

    const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `"${escaped}"`;
  }

  private deriveEnvName(identifier: string): string {
    const normalized = identifier
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
}
