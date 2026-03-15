import * as path from 'path';
import { createHash } from 'crypto';
import { Finding, FindingSeverity } from '../models/Finding';
import { RemediationAction } from '../models/Remediation';

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
      .map((result) => this.toFinding(result, cwd));
  }

  private toFinding(result: SemgrepResult, cwd: string): Finding {
    const severity = this.mapSeverity(result.extra?.severity);
    const rawPath = result.path ?? '';
    const filePath = path.normalize(path.isAbsolute(rawPath) ? rawPath : path.resolve(cwd, rawPath));
    const startLine = result.start?.line ?? 1;
    const startCol = result.start?.col ?? 1;
    const endLine = result.end?.line ?? startLine;
    const endCol = result.end?.col ?? startCol + 1;
    const shortDescription = result.extra?.metadata?.shortDescription ?? result.extra?.metadata?.short_description;
    const message = result.extra?.message ?? 'Semgrep finding';
    const ruleId = result.check_id ?? 'unknown-rule';

    return {
      id: this.makeFindingId(ruleId, filePath, startLine, startCol, message),
      ruleId,
      message,
      severity,
      filePath,
      startLine,
      startCol,
      endLine,
      endCol,
      snippet: result.extra?.lines,
      helpText: shortDescription,
      suggestions: this.buildFallbackSuggestions(ruleId, message, shortDescription)
    };
  }

  private makeFindingId(ruleId: string, filePath: string, startLine: number, startCol: number, message: string): string {
    const base = `${ruleId}|${filePath}|${startLine}|${startCol}|${message}`;
    return createHash('sha1').update(base).digest('hex');
  }

    private buildFallbackSuggestions(ruleId: string, message: string, helpText?: string): RemediationAction[] {
    const key = `${ruleId} ${message} ${helpText ?? ''}`.toLowerCase();
  
    if (this.containsAny(key, ['innerhtml', 'xss'])) {
      return [
        {
          id: `${ruleId}:suggestion:innerhtml`,
          title: 'Replace innerHTML with textContent when possible',
          description: 'Use textContent for plain text. If HTML is truly required, sanitize untrusted input before rendering.',
          detail: 'Use textContent for plain text. If HTML is truly required, sanitize untrusted input before rendering.',
          kind: 'quickfix',
          commandId: 'securelens.quickfix.convertInnerHtml',
          isPreferred: true
        }
      ];
    }
  
    if (this.containsAny(key, ['sql', 'query', 'select', 'insert', 'update', 'delete'])) {
      return [
        {
          id: `${ruleId}:suggestion:sql`,
          title: 'Use parameterized queries',
          description: 'Avoid building SQL statements with string concatenation. Bind user data separately from the SQL text.',
          detail: 'Avoid building SQL statements with string concatenation. Bind user data separately from the SQL text.',
          kind: 'manual', 
          isPreferred: true
        }
      ];
    }
  
    if (this.containsAny(key, ['exec', 'command', 'spawn', 'shell'])) {
      return [
        {
          id: `${ruleId}:suggestion:exec`,
          title: 'Avoid shell command construction from input',
          description: 'Use safe APIs, argument arrays, allowlists, and strict validation for any user-influenced command values.',
          detail: 'Use safe APIs, argument arrays, allowlists, and strict validation for any user-influenced command values.',
          kind: 'manual',
          isPreferred: true
        }
      ];
    }
  
    if (this.containsAny(key, ['eval'])) {
      return [
        {
          id: `${ruleId}:suggestion:eval`,
          title: 'Avoid eval and use safer alternatives',
          description: 'Use JSON.parse, explicit parsers, or dispatch tables instead of executing dynamic code.',
          detail: 'Use JSON.parse, explicit parsers, or dispatch tables instead of executing dynamic code.',
          kind: 'manual',
          commandId: 'securelens.quickfix.showEvalGuidance',
          isPreferred: true
        }
      ];
    }
  
    if (this.containsAny(key, ['secret', 'password', 'credential', 'api key', 'apikey', 'token', 'bearer', 'key'])) {
      return [
        {
          id: `${ruleId}:suggestion:secret`,
          title: 'Move secret to environment variable (.env)',
          description: 'Keep credentials out of source code. Replace the hardcoded literal with an environment variable reference and ensure the variable exists in .env.',
          detail: 'Keep credentials out of source code. Replace the hardcoded literal with an environment variable reference and ensure the variable exists in .env.',
          kind: 'quickfix',
          commandId: 'securelens.quickfix.replaceWithEnv',
          isPreferred: true
        }
      ];
    }
  
    return [];
  }

  private containsAny(value: string, needles: string[]): boolean {
    return needles.some((needle) => value.includes(needle));
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
