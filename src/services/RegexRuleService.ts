import * as path from 'path';
import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import { Finding, FindingSeverity } from '../models/Finding';

interface RegexRule {
  id: string;
  name: string;
  message: string;
  description: string;
  category: 'hardcoded-secret' | 'secret-exposure';
  severity: FindingSeverity;
  supportedExtensions: string[];
}

const SUPPORTED_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.py']);

const SECRET_RULE: RegexRule = {
  id: 'securelens.regex.secret.assignment',
  name: 'Hardcoded secret assignment',
  message: 'Possible hardcoded secret detected. Move this value to an environment variable.',
  description: 'Likely hardcoded secret assigned in code.',
  category: 'hardcoded-secret',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const BEARER_RULE: RegexRule = {
  id: 'securelens.regex.secret.authorization-bearer',
  name: 'Hardcoded bearer token literal',
  message: 'Possible hardcoded bearer token detected. Move this value to an environment variable.',
  description: 'Likely bearer token string literal embedded in code.',
  category: 'hardcoded-secret',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const AUTHORIZATION_SINK_RULE: RegexRule = {
  id: 'securelens.regex.secret-exposure.authorization-header',
  name: 'Secret in Authorization header',
  message: 'Secret-like value used in Authorization header.',
  description: 'Secret-like value is used directly in an Authorization header field.',
  category: 'secret-exposure',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const QUERYSTRING_SINK_RULE: RegexRule = {
  id: 'securelens.regex.secret-exposure.querystring',
  name: 'Secret in query string',
  message: 'Secret-like value concatenated into URL query string.',
  description: 'Secret-like value appears in URL query parameters where it can leak via logs and intermediaries.',
  category: 'secret-exposure',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const LOGGING_SINK_RULE: RegexRule = {
  id: 'securelens.regex.secret-exposure.logging',
  name: 'Secret logged',
  message: 'Secret-like value may be logged to console or logger output.',
  description: 'Logging secret-like values can leak credentials to local and remote logging systems.',
  category: 'secret-exposure',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const ASSIGNMENT_REGEX = /\b([A-Za-z_][A-Za-z0-9_]*)\b\s*[:=]\s*(["'`])([^"'`\n]{8,})\2/g;
const AUTHORIZATION_HEADER_REGEX = /\bAuthorization\b\s*:\s*([A-Za-z_][A-Za-z0-9_]*)/g;
const QUERYSTRING_SECRET_REGEX =
  /["'`][^"'`\n]*\?(?:[^"'`\n]*?(?:key|token|password|secret)=[^"'`\n]*)["'`]\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)/gi;
const LOG_CALL_REGEX = /\b(?:console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug)|print)\s*\(([^)]*)\)/g;
const PLACEHOLDER_PATTERNS = [
  'your_api_key_here',
  'your-token-here',
  'changeme',
  'replace_me',
  'example',
  'sample',
  'dummy',
  'password123'
];
const SECRET_NAME_HINTS = [
  'password',
  'secret',
  'token',
  'apikey',
  'api_key',
  'bearer',
  'auth',
  'clientsecret',
  'client_secret',
  'accesskey',
  'access_key',
  'privatekey',
  'private_key'
];

export class RegexRuleService {
  public async scanTargets(targets: string[]): Promise<Finding[]> {
    const files = await this.resolveTargetFiles(targets);
    const findings: Finding[] = [];

    for (const filePath of files) {
      const fileFindings = await this.scanFile(filePath);
      findings.push(...fileFindings);
    }

    return findings;
  }

  private async resolveTargetFiles(targets: string[]): Promise<string[]> {
    const discovered = new Set<string>();

    for (const target of targets) {
      const normalized = path.normalize(target);
      let stat;

      try {
        stat = await fs.stat(normalized);
      } catch {
        continue;
      }

      if (stat.isFile()) {
        if (this.isSupportedFile(normalized)) {
          discovered.add(normalized);
        }
        continue;
      }

      if (stat.isDirectory()) {
        const nestedFiles = await this.walkDirectory(normalized);
        nestedFiles.forEach((file) => discovered.add(file));
      }
    }

    return Array.from(discovered.values());
  }

  private async walkDirectory(dirPath: string): Promise<string[]> {
    const result: string[] = [];
    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') {
        continue;
      }

      const fullPath = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        const nested = await this.walkDirectory(fullPath);
        result.push(...nested);
        continue;
      }

      if (entry.isFile() && this.isSupportedFile(fullPath)) {
        result.push(path.normalize(fullPath));
      }
    }

    return result;
  }

  private async scanFile(filePath: string): Promise<Finding[]> {
    const extension = path.extname(filePath).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(extension)) {
      return [];
    }

    const source = await fs.readFile(filePath, 'utf8');
    const findings: Finding[] = [];

    for (const match of source.matchAll(ASSIGNMENT_REGEX)) {
      const identifier = match[1] ?? '';
      const literal = match[3] ?? '';
      const fullMatch = match[0] ?? '';

      if (!this.shouldFlag(identifier, literal)) {
        continue;
      }

      const rule = this.isBearerLiteral(literal) ? BEARER_RULE : SECRET_RULE;
      const startOffset = match.index ?? 0;
      const location = this.toLineColumn(source, startOffset, fullMatch.length);

      findings.push(
        this.toFinding({
          rule,
          filePath,
          matchedText: fullMatch,
          startLine: location.startLine,
          startCol: location.startCol,
          endLine: location.endLine,
          endCol: location.endCol
        })
      );
    }

    findings.push(...this.scanSinkUsages(filePath, source));

    return findings;
  }

  private scanSinkUsages(filePath: string, source: string): Finding[] {
    const findings: Finding[] = [];
    const lines = source.split(/\r?\n/);

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const lineNumber = i + 1;

      for (const match of line.matchAll(AUTHORIZATION_HEADER_REGEX)) {
        const identifier = match[1] ?? '';
        if (!this.isSecretLikeIdentifier(identifier)) {
          continue;
        }

        const startCol = (match.index ?? 0) + match[0].lastIndexOf(identifier) + 1;
        findings.push(
          this.toFinding({
            rule: AUTHORIZATION_SINK_RULE,
            filePath,
            matchedText: identifier,
            startLine: lineNumber,
            startCol,
            endLine: lineNumber,
            endCol: startCol + identifier.length
          })
        );
      }

      for (const match of line.matchAll(QUERYSTRING_SECRET_REGEX)) {
        const identifier = match[1] ?? '';
        if (!identifier || !this.isSecretLikeIdentifier(identifier)) {
          continue;
        }

        const idOffset = match[0].lastIndexOf(identifier);
        const startCol = (match.index ?? 0) + Math.max(idOffset, 0) + 1;
        findings.push(
          this.toFinding({
            rule: QUERYSTRING_SINK_RULE,
            filePath,
            matchedText: identifier,
            startLine: lineNumber,
            startCol,
            endLine: lineNumber,
            endCol: startCol + identifier.length
          })
        );
      }

      for (const match of line.matchAll(LOG_CALL_REGEX)) {
        const argsText = match[1] ?? '';
        const callStart = match.index ?? 0;
        const argsStartInLine = callStart + match[0].indexOf(argsText);

        for (const identifierMatch of argsText.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
          const identifier = identifierMatch[1] ?? '';
          if (!this.isSecretLikeIdentifier(identifier)) {
            continue;
          }

          const startCol = argsStartInLine + (identifierMatch.index ?? 0) + 1;
          findings.push(
            this.toFinding({
              rule: LOGGING_SINK_RULE,
              filePath,
              matchedText: identifier,
              startLine: lineNumber,
              startCol,
              endLine: lineNumber,
              endCol: startCol + identifier.length
            })
          );
        }
      }
    }

    return findings;
  }

  private shouldFlag(identifier: string, literal: string): boolean {
    if (!this.isHighSignalLiteral(literal)) {
      return false;
    }

    return this.isSecretLikeIdentifier(identifier) || this.isBearerLiteral(literal);
  }

  private isSecretLikeIdentifier(identifier: string): boolean {
    const normalized = identifier.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
    return SECRET_NAME_HINTS.some((hint) => normalized.includes(hint.replace(/[^A-Za-z0-9]/g, '')));
  }

  private isBearerLiteral(literal: string): boolean {
    return /^bearer\s+[a-z0-9._\-]{10,}$/i.test(literal.trim());
  }

  private isHighSignalLiteral(rawValue: string): boolean {
    const value = rawValue.trim().toLowerCase();

    if (!value || value.length < 8) {
      return false;
    }

    if (PLACEHOLDER_PATTERNS.some((placeholder) => value.includes(placeholder))) {
      return false;
    }

    if (/^[x*_-]+$/i.test(value)) {
      return false;
    }

    return true;
  }

  private toFinding(params: {
    rule: RegexRule;
    filePath: string;
    matchedText: string;
    startLine: number;
    startCol: number;
    endLine: number;
    endCol: number;
  }): Finding {
    const id = this.makeId(params.rule.id, params.filePath, params.startLine, params.startCol, params.rule.message);

    return {
      id,
      ruleId: params.rule.id,
      message: params.rule.message,
      severity: params.rule.severity,
      filePath: params.filePath,
      startLine: params.startLine,
      startCol: params.startCol,
      endLine: params.endLine,
      endCol: params.endCol,
      snippet: params.matchedText,
      helpText: params.rule.description,
      source: 'regex',
      category: params.rule.category
    };
  }

  private makeId(ruleId: string, filePath: string, startLine: number, startCol: number, message: string): string {
    const base = `${ruleId}|${filePath}|${startLine}|${startCol}|${message}`;
    return createHash('sha1').update(base).digest('hex');
  }

  private toLineColumn(content: string, startOffset: number, matchLength: number): {
    startLine: number;
    startCol: number;
    endLine: number;
    endCol: number;
  } {
    const startSlice = content.slice(0, startOffset);
    const startLines = startSlice.split('\n');
    const startLine = startLines.length;
    const startCol = startLines[startLines.length - 1].length + 1;

    const endOffset = startOffset + Math.max(matchLength, 1);
    const endSlice = content.slice(0, endOffset);
    const endLines = endSlice.split('\n');
    const endLine = endLines.length;
    const endCol = endLines[endLines.length - 1].length + 1;

    return { startLine, startCol, endLine, endCol };
  }

  private isSupportedFile(filePath: string): boolean {
    return SUPPORTED_EXTENSIONS.has(path.extname(filePath).toLowerCase());
  }
}
