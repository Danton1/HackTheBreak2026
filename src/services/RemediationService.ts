import { Finding } from '../models/Finding';
import { Remediation, RemediationAction } from '../models/Remediation';

const SECRET_EXPLANATION =
  'This value appears to be a hardcoded credential or secret. Storing secrets directly in source code risks accidental exposure through version control, logs, screenshots, stack traces, or shared repositories.';

const SECRET_SOLUTION =
  'Move the secret into a .env file or another secure secret manager. Replace the hardcoded literal with an environment variable reference such as process.env.MY_API_KEY. Ensure .env is ignored by version control, and consider committing a .env.example file so teammates know which variables are required without exposing real credentials.';

const SECRET_EXPOSURE_EXPLANATION =
  'A secret-like value appears to be used in a high-risk sink such as headers, URL query strings, or logs. This can expose credentials in telemetry, browser history, reverse proxies, or logs.';

const SECRET_EXPOSURE_SOLUTION =
  'Avoid placing secrets in URL query strings or logs. Prefer Authorization headers with short-lived tokens from secure storage, redact sensitive values before logging, and review network/client instrumentation for accidental leakage.';

const SECRET_ACTION: RemediationAction = {
  id: 'secret.env.quickfix',
  title: 'Move secret to environment variable (.env)',
  detail: 'Keep credentials out of source code. Replace the hardcoded literal with an environment variable reference and ensure the variable exists in .env.',
  kind: 'quickfix',
  commandId: 'securelens.quickfix.replaceWithEnv',
  isPreferred: true
};

const REMEDIATION_MAP: Record<string, Remediation> = {
  'securelens.js.hardcoded-password': {
    category: 'hardcoded-secret',
    explanation: SECRET_EXPLANATION,
    detailedSolution: SECRET_SOLUTION,
    suggestedFixes: [SECRET_ACTION],
    canAutoFix: false,
    confidence: 'high',
    references: ['https://12factor.net/config']
  },
  'securelens.regex.secret.assignment': {
    category: 'hardcoded-secret',
    explanation: SECRET_EXPLANATION,
    detailedSolution: SECRET_SOLUTION,
    suggestedFixes: [SECRET_ACTION],
    canAutoFix: false,
    confidence: 'high',
    references: ['https://12factor.net/config']
  },
  'securelens.regex.secret.authorization-bearer': {
    category: 'hardcoded-secret',
    explanation: SECRET_EXPLANATION,
    detailedSolution: SECRET_SOLUTION,
    suggestedFixes: [SECRET_ACTION],
    canAutoFix: false,
    confidence: 'high',
    references: ['https://12factor.net/config']
  },
  'securelens.regex.secret-exposure.authorization-header': {
    category: 'secret-exposure',
    explanation: SECRET_EXPOSURE_EXPLANATION,
    detailedSolution: SECRET_EXPOSURE_SOLUTION,
    suggestedFixes: [],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.regex.secret-exposure.querystring': {
    category: 'secret-exposure',
    explanation: SECRET_EXPOSURE_EXPLANATION,
    detailedSolution: SECRET_EXPOSURE_SOLUTION,
    suggestedFixes: [],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.regex.secret-exposure.logging': {
    category: 'secret-exposure',
    explanation: SECRET_EXPOSURE_EXPLANATION,
    detailedSolution: SECRET_EXPOSURE_SOLUTION,
    suggestedFixes: [],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.js.sql-string-concat': {
    category: 'sql-injection',
    explanation: 'Building SQL statements via string concatenation risks SQL injection when user data is embedded.',
    detailedSolution: 'Switch to parameterized queries or ORM APIs that separate data from SQL syntax. Never inject untrusted input directly into SQL strings.',
    suggestedFixes: [
      {
        id: 'sql.parameterize',
        title: 'Use parameterized queries',
        detail: 'Replace string concatenation with parameterized query APIs (e.g., parameter markers with client libraries).',
        kind: 'manual'
      }
    ],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.js.dangerous-innerhtml': {
    category: 'xss-innerhtml',
    explanation: 'This code treats user input like HTML, which means an attacker could inject script or malicious markup (leading to XSS). If you only want to display text, use textContent instead.',
    detailedSolution: 'Use safe DOM APIs such as textContent when inserting untrusted text. Sanitize any HTML before insertion or avoid innerHTML entirely.',
    suggestedFixes: [
      {
        id: 'innerhtml.to.textcontent',
        title: 'Switch innerHTML to textContent',
        detail: 'Use textContent to prevent HTML parsing when only text is needed.',
        kind: 'quickfix',
        commandId: 'securelens.quickfix.convertInnerHtml'
      }
    ],
    canAutoFix: true,
    autoFixKind: 'text-replace',
    confidence: 'medium'
  },
  'securelens.js.exec-user-input': {
    category: 'command-injection',
    explanation: 'Executing shell commands with user-controlled data can allow arbitrary command execution.',
    detailedSolution: 'Avoid passing unsanitized input into exec/child_process commands. Prefer safe APIs or strict allowlists.',
    suggestedFixes: [
      {
        id: 'exec.manual-allowlist',
        title: 'Review exec usage',
        detail: 'Validate inputs or replace exec with a safer API. Do not interpolate arbitrary user values into shell commands.',
        kind: 'manual'
      }
    ],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.js.eval-usage': {
    category: 'insecure-eval',
    explanation: 'eval can execute attacker-provided code whenever untrusted input reaches it.',
    detailedSolution: 'Avoid eval by parsing or interpreting data manually, or remove the need for dynamic evaluation altogether.',
    suggestedFixes: [
      {
        id: 'eval.guidance',
        title: 'Show safer alternative guidance',
        detail: 'Open remediation guidance about avoiding eval.',
        kind: 'manual',
        commandId: 'securelens.quickfix.showEvalGuidance'
      }
    ],
    canAutoFix: false,
    confidence: 'medium'
  }
};

const FALLBACK_REMEDIATION: Remediation = {
  category: 'generic-security-warning',
  explanation: 'This is a security-related finding that requires review.',
  detailedSolution: 'Investigate the finding details and consult documentation or policies to determine how to fix it.',
  suggestedFixes: [],
  canAutoFix: false,
  confidence: 'low'
};

export class RemediationService {
  private readonly remediations = REMEDIATION_MAP;

  public enrichFinding(finding: Finding): Finding {
    const mapped = this.remediations[finding.ruleId] ?? this.defaultRemediation(finding);
    const existing = finding.suggestions ?? [];
    const suggestions = this.mergeSuggestions(existing, mapped.suggestedFixes);

    const remediation: Remediation = {
      ...mapped,
      suggestedFixes: suggestions
    };

    return {
      ...finding,
      remediation,
      suggestions,
      category: remediation.category,
      explanation: remediation.explanation,
      detailedSolution: remediation.detailedSolution,
      canAutoFix: remediation.canAutoFix,
      autoFixKind: remediation.autoFixKind,
      confidence: remediation.confidence
    };
  }

  private mergeSuggestions(existing: RemediationAction[], incoming: RemediationAction[]): RemediationAction[] {
    const seen = new Set<string>();
    const merged: RemediationAction[] = [];

    for (const item of [...existing, ...incoming]) {
      const key = `${item.commandId ?? ''}|${item.title}|${item.detail ?? ''}|${item.kind ?? ''}`;
      if (seen.has(key)) {
        continue;
      }

      seen.add(key);
      merged.push(item);
    }

    return merged;
  }

  private defaultRemediation(finding: Finding): Remediation {
    const text = `${finding.ruleId} ${finding.message}`.toLowerCase();

    if (text.includes('secret') || text.includes('credential') || text.includes('password') || text.includes('token')) {
      return {
        category: 'hardcoded-secret',
        explanation: SECRET_EXPLANATION,
        detailedSolution: SECRET_SOLUTION,
        suggestedFixes: [SECRET_ACTION],
        canAutoFix: false,
        confidence: 'medium',
        references: ['https://12factor.net/config']
      };
    }

    if (text.includes('authorization header') || text.includes('query string') || text.includes('logged')) {
      return {
        category: 'secret-exposure',
        explanation: SECRET_EXPOSURE_EXPLANATION,
        detailedSolution: SECRET_EXPOSURE_SOLUTION,
        suggestedFixes: [],
        canAutoFix: false,
        confidence: 'medium'
      };
    }

    return FALLBACK_REMEDIATION;
  }
}
