import { Finding } from '../models/Finding';
import { Remediation, RemediationAction } from '../models/Remediation';

const HARD_CODED_SECRET_EXPLANATION =
  'This value looks like a hardcoded secret. Secrets in source code are easy to leak through commits, pull requests, screenshots, logs, and shared environments.';

const HARD_CODED_SECRET_SOLUTION =
  'Move this value into an environment variable (or a secret manager), then reference it from code (for example, process.env.MY_API_KEY). Make sure .env is ignored in version control, keep a .env.example for required keys, and rotate the credential if it may already be exposed.';

const SQL_INJECTION_EXPLANATION =
  'This query appears to be built with string concatenation. If user-controlled input is mixed into SQL text, an attacker may be able to change query behavior and read or modify data.';

const SQL_INJECTION_SOLUTION =
  'Convert this query to a parameterized query (prepared statement) so data is passed separately from SQL syntax. If you use an ORM, prefer parameter APIs instead of raw string concatenation.';

const XSS_EXPLANATION =
  'This code inserts dynamic content with innerHTML. If that content is influenced by user input, the browser may treat it as real HTML or script, which can lead to cross-site scripting (XSS).';

const XSS_SOLUTION =
  'If you are rendering plain text, use textContent instead of innerHTML. If HTML rendering is required, sanitize the content first and limit where untrusted markup can be rendered.';

const COMMAND_INJECTION_EXPLANATION =
  'This code may execute a shell command built from dynamic input. If user-controlled values reach command execution, attackers may run unintended system commands.';

const COMMAND_INJECTION_SOLUTION =
  'Avoid building shell commands with string concatenation. Prefer safer APIs that use argument arrays, validate values with strict allowlists, and never pass raw user input directly into shell execution.';

const EVAL_EXPLANATION =
  'This code uses dynamic evaluation. If untrusted input reaches eval/new Function, it can execute arbitrary JavaScript in your runtime.';

const EVAL_SOLUTION =
  'Avoid eval and new Function where possible. Use JSON.parse for data, explicit parsing logic, or a dispatch table for controlled behavior instead of executing dynamic code.';

const SECRET_EXPOSURE_EXPLANATION =
  'A secret-like value appears in a risky sink (URL, header, or logs). These locations are often captured by proxies, browser history, monitoring tools, and log pipelines.';

const SECRET_EXPOSURE_SOLUTION =
  'Do not put secrets in query strings or logs. Keep sensitive values out of debug output, mask tokens when needed, and review request/auth handling so credentials are sent and stored in safer ways.';

const GENERIC_EXPLANATION =
  'SecureLens found a security-related pattern that deserves a quick review.';

const GENERIC_SOLUTION =
  'Validate how data flows into this code path, use safer APIs where available, and prefer explicit validation/sanitization over implicit assumptions.';

const SECRET_ACTION: RemediationAction = {
  id: 'secret.env.quickfix',
  title: 'Replace hardcoded secret with process.env variable',
  detail:
    'Convert this literal to process.env.<NAME>, then store the real value in .env (or a secret manager). Rotate the credential if it may have been exposed.',
  kind: 'quickfix',
  commandId: 'securelens.quickfix.replaceWithEnv',
  isPreferred: true
};

const INNER_HTML_ACTION: RemediationAction = {
  id: 'innerhtml.to.textcontent',
  title: 'Replace innerHTML with textContent for plain text',
  detail: 'Use textContent when you do not need HTML rendering to reduce XSS risk.',
  kind: 'quickfix',
  commandId: 'securelens.quickfix.convertInnerHtml'
};

const EVAL_GUIDANCE_ACTION: RemediationAction = {
  id: 'eval.guidance',
  title: 'Show safer alternatives to eval',
  detail: 'Open guidance for replacing eval/new Function with explicit parsing or dispatch logic.',
  kind: 'manual',
  commandId: 'securelens.quickfix.showEvalGuidance'
};

const SQL_PARAMETERIZE_ACTION: RemediationAction = {
  id: 'sql.parameterize',
  title: 'Convert this query to a parameterized query',
  detail: 'Keep user input out of SQL strings by using prepared statements or ORM parameter bindings.',
  kind: 'manual'
};

const COMMAND_REVIEW_ACTION: RemediationAction = {
  id: 'exec.manual-allowlist',
  title: 'Review how this command is built',
  detail: 'Avoid passing user input into shell commands. Prefer argument arrays and strict allowlists.',
  kind: 'manual'
};

const REMEDIATION_MAP: Record<string, Remediation> = {
  'securelens.js.hardcoded-password': {
    category: 'hardcoded-secret',
    explanation: HARD_CODED_SECRET_EXPLANATION,
    detailedSolution: HARD_CODED_SECRET_SOLUTION,
    suggestedFixes: [SECRET_ACTION],
    canAutoFix: false,
    confidence: 'high',
    references: ['https://12factor.net/config']
  },
  'securelens.regex.secret.assignment': {
    category: 'hardcoded-secret',
    explanation: HARD_CODED_SECRET_EXPLANATION,
    detailedSolution: HARD_CODED_SECRET_SOLUTION,
    suggestedFixes: [SECRET_ACTION],
    canAutoFix: false,
    confidence: 'high',
    references: ['https://12factor.net/config']
  },
  'securelens.regex.secret.authorization-bearer': {
    category: 'hardcoded-secret',
    explanation: HARD_CODED_SECRET_EXPLANATION,
    detailedSolution: HARD_CODED_SECRET_SOLUTION,
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
    explanation: SQL_INJECTION_EXPLANATION,
    detailedSolution: SQL_INJECTION_SOLUTION,
    suggestedFixes: [SQL_PARAMETERIZE_ACTION],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.regex.sql.concat': {
    category: 'sql-injection',
    explanation: SQL_INJECTION_EXPLANATION,
    detailedSolution: SQL_INJECTION_SOLUTION,
    suggestedFixes: [SQL_PARAMETERIZE_ACTION],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.js.dangerous-innerhtml': {
    category: 'xss-innerhtml',
    explanation: XSS_EXPLANATION,
    detailedSolution: XSS_SOLUTION,
    suggestedFixes: [INNER_HTML_ACTION],
    canAutoFix: true,
    autoFixKind: 'text-replace',
    confidence: 'medium'
  },
  'securelens.regex.xss.innerhtml': {
    category: 'xss-innerhtml',
    explanation: XSS_EXPLANATION,
    detailedSolution: XSS_SOLUTION,
    suggestedFixes: [INNER_HTML_ACTION],
    canAutoFix: true,
    autoFixKind: 'text-replace',
    confidence: 'medium'
  },
  'securelens.js.exec-user-input': {
    category: 'command-injection',
    explanation: COMMAND_INJECTION_EXPLANATION,
    detailedSolution: COMMAND_INJECTION_SOLUTION,
    suggestedFixes: [COMMAND_REVIEW_ACTION],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.regex.command.exec': {
    category: 'command-injection',
    explanation: COMMAND_INJECTION_EXPLANATION,
    detailedSolution: COMMAND_INJECTION_SOLUTION,
    suggestedFixes: [COMMAND_REVIEW_ACTION],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.js.eval-usage': {
    category: 'insecure-eval',
    explanation: EVAL_EXPLANATION,
    detailedSolution: EVAL_SOLUTION,
    suggestedFixes: [EVAL_GUIDANCE_ACTION],
    canAutoFix: false,
    confidence: 'medium'
  },
  'securelens.regex.insecure-eval': {
    category: 'insecure-eval',
    explanation: EVAL_EXPLANATION,
    detailedSolution: EVAL_SOLUTION,
    suggestedFixes: [EVAL_GUIDANCE_ACTION],
    canAutoFix: false,
    confidence: 'medium'
  }
};

const FALLBACK_REMEDIATION: Remediation = {
  category: 'generic-security-warning',
  explanation: GENERIC_EXPLANATION,
  detailedSolution: GENERIC_SOLUTION,
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
        explanation: HARD_CODED_SECRET_EXPLANATION,
        detailedSolution: HARD_CODED_SECRET_SOLUTION,
        suggestedFixes: [SECRET_ACTION],
        canAutoFix: false,
        confidence: 'medium',
        references: ['https://12factor.net/config']
      };
    }

    if (text.includes('innerhtml') || text.includes('xss')) {
      return {
        category: 'xss-innerhtml',
        explanation: XSS_EXPLANATION,
        detailedSolution: XSS_SOLUTION,
        suggestedFixes: [INNER_HTML_ACTION],
        canAutoFix: true,
        autoFixKind: 'text-replace',
        confidence: 'medium'
      };
    }

    if (text.includes('eval') || text.includes('new function') || text.includes('dynamic code')) {
      return {
        category: 'insecure-eval',
        explanation: EVAL_EXPLANATION,
        detailedSolution: EVAL_SOLUTION,
        suggestedFixes: [EVAL_GUIDANCE_ACTION],
        canAutoFix: false,
        confidence: 'medium'
      };
    }

    if (text.includes('sql')) {
      return {
        category: 'sql-injection',
        explanation: SQL_INJECTION_EXPLANATION,
        detailedSolution: SQL_INJECTION_SOLUTION,
        suggestedFixes: [SQL_PARAMETERIZE_ACTION],
        canAutoFix: false,
        confidence: 'medium'
      };
    }

    if (text.includes('command') || text.includes('exec') || text.includes('shell')) {
      return {
        category: 'command-injection',
        explanation: COMMAND_INJECTION_EXPLANATION,
        detailedSolution: COMMAND_INJECTION_SOLUTION,
        suggestedFixes: [COMMAND_REVIEW_ACTION],
        canAutoFix: false,
        confidence: 'medium'
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
