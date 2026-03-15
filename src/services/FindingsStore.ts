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

    for (const [findingId, finding] of this.findingsById.entries()) {
      if (path.normalize(finding.filePath) === normalizedTarget) {
        this.findingsById.delete(findingId);
      }
    }

    for (const finding of findings) {
      this.findingsById.set(finding.id, finding);
    }

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

  public dispose(): void {
    this.onDidChangeEmitter.dispose();
  }
}
