import * as path from 'path';
import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import { Finding, FindingSeverity } from '../models/Finding';

interface RegexRule {
  id: string;
  name: string;
  description: string;
  category: 'hardcoded-secret';
  severity: FindingSeverity;
  supportedExtensions: string[];
}

const SUPPORTED_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.py']);

const SECRET_RULE: RegexRule = {
  id: 'securelens.regex.secret.assignment',
  name: 'Hardcoded secret assignment',
  description: 'Likely hardcoded secret assigned in code.',
  category: 'hardcoded-secret',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const BEARER_RULE: RegexRule = {
  id: 'securelens.regex.secret.authorization-bearer',
  name: 'Hardcoded bearer token literal',
  description: 'Likely bearer token string literal embedded in code.',
  category: 'hardcoded-secret',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const ASSIGNMENT_REGEX = /\b([A-Za-z_][A-Za-z0-9_]*)\b\s*[:=]\s*(["'`])([^"'`\n]{8,})\2/g;
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
    const message = 'Possible hardcoded secret detected. Move this value to an environment variable.';
    const id = this.makeId(params.rule.id, params.filePath, params.startLine, params.startCol, message);

    return {
      id,
      ruleId: params.rule.id,
      message,
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
