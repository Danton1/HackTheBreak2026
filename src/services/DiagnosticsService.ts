import * as vscode from 'vscode';
import { Finding, findingToRange } from '../models/Finding';

export class DiagnosticsService {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('securelens');
  }

  public getCollection(): vscode.DiagnosticCollection {
    return this.collection;
  }

  public clearAll(): void {
    this.collection.clear();
  }

  public clearFile(uri: vscode.Uri): void {
    this.collection.delete(uri);
  }

  public applyFindings(findings: Finding[]): void {
    const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
      const diagnostic = new vscode.Diagnostic(
        findingToRange(finding),
        this.buildMessage(finding),
        this.toDiagnosticSeverity(finding.severity)
      );
      diagnostic.source = 'SecureLens';
      diagnostic.code = finding.ruleId;

      const fileDiagnostics = diagnosticsByFile.get(finding.filePath) ?? [];
      fileDiagnostics.push(diagnostic);
      diagnosticsByFile.set(finding.filePath, fileDiagnostics);
    }

    for (const [filePath, diagnostics] of diagnosticsByFile.entries()) {
      this.collection.set(vscode.Uri.file(filePath), diagnostics);
    }
  }

  public dispose(): void {
    this.collection.dispose();
  }

  private buildMessage(finding: Finding): string {
    if (!finding.helpText) {
      return finding.message;
    }

    return `${finding.message} (${finding.helpText})`;
  }

  private toDiagnosticSeverity(severity: Finding['severity']): vscode.DiagnosticSeverity {
    switch (severity) {
      case 'ERROR':
        return vscode.DiagnosticSeverity.Error;
      case 'INFO':
        return vscode.DiagnosticSeverity.Information;
      case 'WARNING':
      default:
        return vscode.DiagnosticSeverity.Warning;
    }
  }
}
