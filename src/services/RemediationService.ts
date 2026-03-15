import { Finding } from '../models/Finding';
import { Remediation, RemediationAction } from '../models/Remediation';

const SECRET_SOLUTION =
  'Move the secret into a .env file or another secure secret manager. Replace the literal with an environment variable reference such as process.env.MY_SECRET. Ensure .env is ignored in git and consider adding a .env.example file to document the required variables.';

const SECRET_EXPLANATION =
  'This value appears to be a hardcoded credential or secret. Storing secrets directly in source risks accidental exposure through version control, logs, or shared copies.';

const REMEDIATION_MAP: Record<string, Remediation> = {
  'securelens.js.hardcoded-password': {
    category: 'hardcoded-secret',
    explanation: SECRET_EXPLANATION,
    detailedSolution: SECRET_SOLUTION,
    suggestedFixes: [
      {
        id: 'secret.env.placeholder',
        title: 'Use process.env.SECRET_VALUE',
        detail: 'Replace the literal with an env var reference like process.env.SECRET_VALUE.',
        kind: 'quickfix',
        commandId: 'securelens.quickfix.replaceWithEnv',
        isPreferred: true
      }
    ],
    canAutoFix: false,
    autoFixKind: undefined,
    confidence: 'high',
    references: ['https://12factor.net/config']
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

const ENV_REMOTE_ACTION: RemediationAction = {
  id: 'secret.env.placeholder',
  title: 'Replace literal with process.env.SECRET_VALUE',
  detail: 'Substitute literal declaration with an environment variable reference (process.env.SECRET_VALUE).',
  kind: 'quickfix',
  commandId: 'securelens.quickfix.replaceWithEnv',
  isPreferred: true
};

export class RemediationService {
  private readonly remediations = REMEDIATION_MAP;

  public enrichFinding(finding: Finding): Finding {
    const remediation = this.remediations[finding.ruleId] ?? this.defaultRemediation(finding);
    return {
      ...finding,
      remediation,
      suggestions: remediation.suggestedFixes,
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
    const merged = [...existing, ...incoming].filter((item) => {
      const key = item.id || `${item.title}|${item.detail ?? ''}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  
    return merged;
  }

  private defaultRemediation(finding: Finding): Remediation {
    const base: Remediation = {
      ...FALLBACK_REMEDIATION,
      detailedSolution: FALLBACK_REMEDIATION.detailedSolution,
      suggestedFixes: [],
      canAutoFix: false,
      confidence: 'low'
    };

    if (finding.message.toLowerCase().includes('secret') || finding.message.toLowerCase().includes('credential')) {
      return {
        ...base,
        category: 'hardcoded-secret',
        explanation: SECRET_EXPLANATION,
        detailedSolution: SECRET_SOLUTION,
        suggestedFixes: [ENV_REMOTE_ACTION],
        confidence: 'medium'
      };
    }

    return base;
  }
}


