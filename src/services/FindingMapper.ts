import * as path from 'path';
import { Finding, FindingSeverity } from '../models/Finding';

interface SemgrepPosition {
  line?: number;
  col?: number;
}

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: SemgrepPosition;
  end?: SemgrepPosition;
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: {
      shortDescription?: string;
      short_description?: string;
      cwe?: string | string[];
      owasp?: string | string[];
    };
  };
}

interface SemgrepJsonOutput {
  results?: SemgrepResult[];
}

export class FindingMapper {
  public map(rawJson: string, cwd: string): Finding[] {
    const parsed = JSON.parse(rawJson) as SemgrepJsonOutput;
    const results = parsed.results ?? [];

    return results
      .filter((result) => result.path && result.check_id && result.extra?.message)
      .map((result, index) => this.toFinding(result, index, cwd));
  }

  private toFinding(result: SemgrepResult, index: number, cwd: string): Finding {
    const severity = this.mapSeverity(result.extra?.severity);
    const rawPath = result.path ?? '';
    const filePath = path.normalize(path.isAbsolute(rawPath) ? rawPath : path.resolve(cwd, rawPath));
    const startLine = result.start?.line ?? 1;
    const startCol = result.start?.col ?? 1;
    const endLine = result.end?.line ?? startLine;
    const endCol = result.end?.col ?? startCol + 1;
    const shortDescription = result.extra?.metadata?.shortDescription ?? result.extra?.metadata?.short_description;

    return {
      id: `${result.check_id}:${filePath}:${startLine}:${startCol}:${index}`,
      ruleId: result.check_id ?? 'unknown-rule',
      message: result.extra?.message ?? 'Semgrep finding',
      severity,
      filePath,
      startLine,
      startCol,
      endLine,
      endCol,
      snippet: result.extra?.lines,
      helpText: shortDescription
    };
  }

  private mapSeverity(value?: string): FindingSeverity {
    const normalized = (value ?? '').toUpperCase();

    if (normalized === 'ERROR') {
      return 'ERROR';
    }

    if (normalized === 'INFO') {
      return 'INFO';
    }

    return 'WARNING';
  }
}
