import { Suggestion } from './Suggestion';

export type RemediationConfidence = 'high' | 'medium' | 'low';

export interface RemediationAction extends Suggestion {
  kind: 'manual' | 'quickfix' | 'autofix';
  commandId?: string;
  isPreferred?: boolean;
  description?: string;
}

export interface Remediation {
  category: string;
  explanation: string;
  detailedSolution: string;
  suggestedFixes: RemediationAction[];
  canAutoFix: boolean;
  autoFixKind?: string;
  confidence: RemediationConfidence;
  references?: string[];
}
