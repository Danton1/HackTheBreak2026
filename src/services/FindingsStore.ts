import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from '../models/Finding';

export class FindingsStore implements vscode.Disposable {
  private readonly onDidChangeEmitter = new vscode.EventEmitter<void>();
  private findingsById = new Map<string, Finding>();
  private dismissedIds = new Set<string>();

  public readonly onDidChange = this.onDidChangeEmitter.event;

  public getActiveFindings(): Finding[] {
    return Array.from(this.findingsById.values()).filter((finding) => !this.dismissedIds.has(finding.id));
  }

  public replaceAll(findings: Finding[]): void {
    this.findingsById = new Map(findings.map((finding) => [finding.id, finding]));
    this.dismissedIds.clear();
    this.onDidChangeEmitter.fire();
  }

  public getFindingById(findingId: string): Finding | undefined {
    const finding = this.findingsById.get(findingId);

    if (!finding) {
      return undefined;
    }

    if (this.dismissedIds.has(findingId)) {
      return undefined;
    }

    return finding;
  }

  public replaceForFile(filePath: string, findings: Finding[]): void {
    const normalizedTarget = path.normalize(filePath);
    const replacedFindingIds = new Set<string>();

    for (const [findingId, finding] of this.findingsById.entries()) {
      if (path.normalize(finding.filePath) === normalizedTarget) {
        this.findingsById.delete(findingId);
        replacedFindingIds.add(findingId);
      }
    }

    for (const finding of findings) {
      this.findingsById.set(finding.id, finding);
      replacedFindingIds.add(finding.id);
    }

    this.clearDismissedIds(replacedFindingIds);
    this.onDidChangeEmitter.fire();
  }

  public dismissFinding(findingOrId: Finding | string): void {
    const findingId = typeof findingOrId === 'string' ? findingOrId : findingOrId.id;

    if (!this.findingsById.has(findingId)) {
      return;
    }

    this.dismissedIds.add(findingId);
    this.onDidChangeEmitter.fire();
  }

  public dismissAllFindings(): void {
    const activeFindings = this.getActiveFindings();
    if (activeFindings.length === 0) {
      return;
    }

    for (const finding of activeFindings) {
      this.dismissedIds.add(finding.id);
    }

    this.onDidChangeEmitter.fire();
  }

  public dispose(): void {
    this.onDidChangeEmitter.dispose();
  }

  private clearDismissedIds(idsToClear: Set<string>): void {
    if (idsToClear.size === 0) {
      return;
    }

    this.dismissedIds = new Set(
      Array.from(this.dismissedIds).filter((findingId) => !idsToClear.has(findingId))
    );
  }
}
