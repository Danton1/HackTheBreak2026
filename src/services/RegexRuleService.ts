import * as path from 'path';
import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import * as vscode from 'vscode';
import { Finding, FindingSeverity } from '../models/Finding';

interface RegexRule {
  id: string;
  name: string;
  message: string;
  description: string;
  category:
    | 'hardcoded-secret'
    | 'secret-exposure'
    | 'xss-innerhtml'
    | 'insecure-eval'
    | 'command-injection'
    | 'sql-injection';
  severity: FindingSeverity;
  supportedExtensions: string[];
}

interface CustomRegexRuleConfig {
  id?: unknown;
  name?: unknown;
  pattern?: unknown;
  flags?: unknown;
  severity?: unknown;
  category?: unknown;
  message?: unknown;
  explanation?: unknown;
  detailedSolution?: unknown;
  fileExtensions?: unknown;
  source?: unknown;
}

interface CompiledCustomRegexRule {
  id: string;
  name: string;
  regex: RegExp;
  severity: FindingSeverity;
  category: string;
  message: string;
  explanation?: string;
  detailedSolution?: string;
  fileExtensions: Set<string>;
  source: 'regex' | 'custom-regex';
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

const INNER_HTML_RULE: RegexRule = {
  id: 'securelens.regex.xss.innerhtml',
  name: 'innerHTML dynamic usage',
  message: 'Potential XSS: innerHTML used with dynamic content.',
  description: 'innerHTML can execute or render untrusted markup when fed user-controlled data.',
  category: 'xss-innerhtml',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx']
};

const EVAL_RULE: RegexRule = {
  id: 'securelens.regex.insecure-eval',
  name: 'Dynamic code execution',
  message: 'Dynamic code execution detected.',
  description: 'eval/new Function can execute attacker-controlled strings.',
  category: 'insecure-eval',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx']
};

const COMMAND_EXEC_RULE: RegexRule = {
  id: 'securelens.regex.command.exec',
  name: 'Unsafe command execution',
  message: 'Potential command injection or unsafe process execution.',
  description: 'exec/execSync/spawn with shell can execute untrusted command strings.',
  category: 'command-injection',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const SQL_CONCAT_RULE: RegexRule = {
  id: 'securelens.regex.sql.concat',
  name: 'SQL query concatenation',
  message: 'Potential SQL injection: query built with string concatenation.',
  description: 'SQL built by concatenating variables can allow injection.',
  category: 'sql-injection',
  severity: 'WARNING',
  supportedExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py']
};

const ASSIGNMENT_REGEX = /\b([A-Za-z_][A-Za-z0-9_]*)\b\s*[:=]\s*(["'`])([^"'`\n]{8,})\2/g;
const AUTHORIZATION_HEADER_REGEX = /\bAuthorization\b\s*:\s*([A-Za-z_][A-Za-z0-9_]*)/g;
const QUERYSTRING_SECRET_REGEX =
  /["'`][^"'`\n]*\?(?:[^"'`\n]*?(?:key|token|password|secret)=[^"'`\n]*)["'`]\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)/gi;
const LOG_CALL_REGEX = /\b(?:console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug)|print)\s*\(([^)]*)\)/g;
const INNER_HTML_REGEX = /\binnerHTML\b\s*=/g;
const EVAL_REGEX = /\beval\s*\(|\bnew\s+Function\s*\(/g;
const COMMAND_EXEC_REGEX =
  /\b(?:child_process\.)?(?:exec|execSync)\s*\(|\brequire\((["'`])child_process\1\)\.(?:exec|execSync|spawn)\s*\(|\bspawn\s*\([^)]*\{[^}]*\bshell\s*:\s*true/gi;
const SQL_CONCAT_REGEX =
  /["'`]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'`\n]*["'`]\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)/gi;

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
    const customRules = this.loadCustomRegexRules();
    const findings: Finding[] = [];

    for (const filePath of files) {
      const fileFindings = await this.scanFile(filePath, customRules);
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

  private async scanFile(filePath: string, customRules: CompiledCustomRegexRule[]): Promise<Finding[]> {
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
    findings.push(...this.scanFallbackRiskyPatterns(filePath, source));
    findings.push(...this.scanCustomRules(filePath, source, extension, customRules));

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

  private scanFallbackRiskyPatterns(filePath: string, source: string): Finding[] {
    const findings: Finding[] = [];
    const lines = source.split(/\r?\n/);

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const lineNumber = i + 1;

      for (const match of line.matchAll(INNER_HTML_REGEX)) {
        const matchedText = match[0] ?? 'innerHTML =';
        findings.push(
          this.toFinding({
            rule: INNER_HTML_RULE,
            filePath,
            matchedText,
            startLine: lineNumber,
            startCol: (match.index ?? 0) + 1,
            endLine: lineNumber,
            endCol: (match.index ?? 0) + matchedText.length + 1
          })
        );
      }

      for (const match of line.matchAll(EVAL_REGEX)) {
        const matchedText = match[0] ?? 'eval(';
        findings.push(
          this.toFinding({
            rule: EVAL_RULE,
            filePath,
            matchedText,
            startLine: lineNumber,
            startCol: (match.index ?? 0) + 1,
            endLine: lineNumber,
            endCol: (match.index ?? 0) + matchedText.length + 1
          })
        );
      }

      for (const match of line.matchAll(COMMAND_EXEC_REGEX)) {
        const matchedText = match[0] ?? 'exec(';
        findings.push(
          this.toFinding({
            rule: COMMAND_EXEC_RULE,
            filePath,
            matchedText,
            startLine: lineNumber,
            startCol: (match.index ?? 0) + 1,
            endLine: lineNumber,
            endCol: (match.index ?? 0) + matchedText.length + 1
          })
        );
      }

      for (const match of line.matchAll(SQL_CONCAT_REGEX)) {
        const matchedText = match[0] ?? 'SELECT ... + value';
        findings.push(
          this.toFinding({
            rule: SQL_CONCAT_RULE,
            filePath,
            matchedText,
            startLine: lineNumber,
            startCol: (match.index ?? 0) + 1,
            endLine: lineNumber,
            endCol: (match.index ?? 0) + matchedText.length + 1
          })
        );
      }
    }

    return findings;
  }

  private scanCustomRules(
    filePath: string,
    source: string,
    extension: string,
    customRules: CompiledCustomRegexRule[]
  ): Finding[] {
    const findings: Finding[] = [];

    for (const rule of customRules) {
      if (rule.fileExtensions.size > 0 && !rule.fileExtensions.has(extension)) {
        continue;
      }

      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.regex.exec(source)) !== null) {
        const matchedText = match[0] ?? '';
        const startOffset = match.index ?? 0;
        const location = this.toLineColumn(source, startOffset, Math.max(matchedText.length, 1));

        findings.push(this.toFindingFromCustomRule(rule, filePath, matchedText, location));

        if (matchedText.length === 0) {
          rule.regex.lastIndex += 1;
        }
      }
    }

    return findings;
  }

  private loadCustomRegexRules(): CompiledCustomRegexRule[] {
    const config = vscode.workspace.getConfiguration('securelens');
    const rawRules = config.get<unknown[]>('customRegexRules', []);

    if (!Array.isArray(rawRules)) {
      return [];
    }

    const compiled: CompiledCustomRegexRule[] = [];

    rawRules.forEach((rawRule, index) => {
      const parsed = this.toCompiledCustomRule(rawRule as CustomRegexRuleConfig, index);
      if (parsed) {
        compiled.push(parsed);
      }
    });

    return compiled;
  }

  private toCompiledCustomRule(raw: CustomRegexRuleConfig, index: number): CompiledCustomRegexRule | undefined {
    if (!raw || typeof raw !== 'object') {
      return undefined;
    }

    const pattern = typeof raw.pattern === 'string' ? raw.pattern : '';
    const message = typeof raw.message === 'string' ? raw.message : '';

    if (!pattern.trim() || !message.trim()) {
      return undefined;
    }

    const id = typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : `custom.regex.rule.${index + 1}`;
    const name = typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : id;
    const flags = this.ensureGlobalFlag(typeof raw.flags === 'string' ? raw.flags : '');

    let regex: RegExp;
    try {
      regex = new RegExp(pattern, flags);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      console.warn(`[SecureLens] Skipping invalid custom regex rule "${id}": ${reason}`);
      return undefined;
    }

    const fileExtensions = this.normalizeCustomFileExtensions(raw.fileExtensions);

    const sourceValue = typeof raw.source === 'string' ? raw.source : 'custom-regex';
    const source: 'regex' | 'custom-regex' = sourceValue === 'regex' ? 'regex' : 'custom-regex';

    return {
      id,
      name,
      regex,
      severity: this.toSeverity(raw.severity),
      category: typeof raw.category === 'string' && raw.category.trim() ? raw.category.trim() : 'generic-security-warning',
      message: message.trim(),
      explanation: typeof raw.explanation === 'string' && raw.explanation.trim() ? raw.explanation.trim() : undefined,
      detailedSolution:
        typeof raw.detailedSolution === 'string' && raw.detailedSolution.trim() ? raw.detailedSolution.trim() : undefined,
      fileExtensions,
      source
    };
  }

  private ensureGlobalFlag(flags: string): string {
    const sanitized = flags.replace(/[^dgimsuvy]/g, '');
    const unique = Array.from(new Set(sanitized.split(''))).join('');

    if (unique.includes('g')) {
      return unique;
    }

    return `${unique}g`;
  }

  private normalizeCustomFileExtensions(value: unknown): Set<string> {
    if (!Array.isArray(value)) {
      return new Set(SUPPORTED_EXTENSIONS);
    }

    const normalized = value
      .filter((item): item is string => typeof item === 'string')
      .map((item) => item.trim().toLowerCase())
      .filter((item) => item.startsWith('.'));

    if (normalized.length === 0) {
      return new Set(SUPPORTED_EXTENSIONS);
    }

    return new Set(normalized);
  }

  private toSeverity(value: unknown): FindingSeverity {
    if (value === 'ERROR' || value === 'INFO' || value === 'WARNING') {
      return value;
    }

    return 'WARNING';
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

  private toFindingFromCustomRule(
    rule: CompiledCustomRegexRule,
    filePath: string,
    matchedText: string,
    location: { startLine: number; startCol: number; endLine: number; endCol: number }
  ): Finding {
    const id = this.makeId(rule.id, filePath, location.startLine, location.startCol, rule.message);

    return {
      id,
      ruleId: rule.id,
      message: rule.message,
      severity: rule.severity,
      filePath,
      startLine: location.startLine,
      startCol: location.startCol,
      endLine: location.endLine,
      endCol: location.endCol,
      snippet: matchedText,
      helpText: rule.name,
      source: rule.source,
      category: rule.category,
      explanation: rule.explanation,
      detailedSolution: rule.detailedSolution
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
