import * as path from 'path';
import * as vscode from 'vscode';
import { Finding, findingToRange } from './models/Finding';
import { SecureLensCodeActionProvider } from './providers/SecureLensCodeActionProvider';
import { DiagnosticsService } from './services/DiagnosticsService';
import { FindingMapper } from './services/FindingMapper';
import { FindingsStore } from './services/FindingsStore';
import { RegexRuleService } from './services/RegexRuleService';
import { RemediationService } from './services/RemediationService';
import { SemgrepService } from './services/SemgrepService';
import { ActionsTreeProvider } from './views/ActionsTreeProvider';
import { FindingsTreeProvider } from './views/FindingsTreeProvider';
import { SuggestionsTreeProvider } from './views/SuggestionsTreeProvider';

interface ScanDependencies {
  outputChannel: vscode.OutputChannel;
  semgrepService: SemgrepService;
  findingMapper: FindingMapper;
  regexRuleService: RegexRuleService;
  findingsStore: FindingsStore;
  remediationService: RemediationService;
}

export function activate(context: vscode.ExtensionContext): void {
  const outputChannel = vscode.window.createOutputChannel('SecureLens');
  const diagnosticsService = new DiagnosticsService();
  const semgrepService = new SemgrepService(context.extensionPath);
  const findingMapper = new FindingMapper();
  const regexRuleService = new RegexRuleService();
  const findingsStore = new FindingsStore();
  const remediationService = new RemediationService();

  const actionsTreeProvider = new ActionsTreeProvider();
  const findingsTreeProvider = new FindingsTreeProvider();
  const suggestionsTreeProvider = new SuggestionsTreeProvider();

  const actionsTreeView = vscode.window.createTreeView('securelens.actionsView', {
    treeDataProvider: actionsTreeProvider,
    showCollapseAll: false
  });

  const findingsTreeView = vscode.window.createTreeView('securelens.findingsView', {
    treeDataProvider: findingsTreeProvider,
    showCollapseAll: false
  });

  const suggestionsTreeView = vscode.window.createTreeView('securelens.suggestionsView', {
    treeDataProvider: suggestionsTreeProvider,
    showCollapseAll: false
  });

  const syncUiFromStore = (): void => {
    const activeFindings = findingsStore.getActiveFindings();
    diagnosticsService.applyFindings(activeFindings);
    findingsTreeProvider.setFindings(activeFindings);
    suggestionsTreeProvider.setFindings(activeFindings);
  };

  const registerCommand = (command: string, handler: (...args: any[]) => any): vscode.Disposable => {
    return vscode.commands.registerCommand(command, handler);
  };

  const codeActionProvider = new SecureLensCodeActionProvider(findingsStore);

  const subscriptions: vscode.Disposable[] = [
    outputChannel,
    diagnosticsService,
    findingsStore,
    actionsTreeProvider,
    findingsTreeProvider,
    suggestionsTreeProvider,
    actionsTreeView,
    findingsTreeView,
    suggestionsTreeView,
    findingsStore.onDidChange(syncUiFromStore),
    registerCommand('securelens.scanCurrentFile', async () => {
      await scanCurrentFile({
        outputChannel,
        semgrepService,
        findingMapper,
        regexRuleService,
        findingsStore,
        remediationService
      });
    }),
    registerCommand('securelens.scanWorkspace', async () => {
      await scanWorkspace({
        outputChannel,
        semgrepService,
        findingMapper,
        regexRuleService,
        findingsStore,
        remediationService
      });
    }),
    registerCommand('securelens.openFinding', async (finding: Finding) => {
      await openFinding(finding);
    }),
    registerCommand('securelens.dismissFinding', (arg: unknown) => {
      const findingId = extractFindingId(arg);
      if (!findingId) {
        return;
      }

      findingsStore.dismissFinding(findingId);
    }),
    registerCommand('securelens.quickfix.showEvalGuidance', async (finding?: Finding) => {
      const message =
        finding?.detailedSolution ??
        'Avoid eval. Prefer JSON.parse, explicit parsing, or a dispatch table instead of dynamic code execution.';

      await vscode.window.showWarningMessage(message, { modal: true });
    }),
    vscode.languages.registerCodeActionsProvider(
      [
        { scheme: 'file', language: 'javascript' },
        { scheme: 'file', language: 'typescript' },
        { scheme: 'file', language: 'javascriptreact' },
        { scheme: 'file', language: 'typescriptreact' },
        { scheme: 'file', language: 'python' }
      ],
      codeActionProvider,
      {
        providedCodeActionKinds: SecureLensCodeActionProvider.providedCodeActionKinds
      }
    )
  ];

  context.subscriptions.push(...subscriptions);
  syncUiFromStore();
}

export function deactivate(): void {
  // VS Code disposes subscriptions registered during activation.
}

async function scanCurrentFile(deps: ScanDependencies): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor || editor.document.uri.scheme !== 'file') {
    vscode.window.showWarningMessage('SecureLens needs an open file to scan the current file.');
    return;
  }

  const filePath = editor.document.uri.fsPath;

  await runScan(
    {
      kind: 'current file',
      targets: [filePath],
      cwd: path.dirname(filePath)
    },
    deps,
    (findings) => {
      deps.findingsStore.replaceForFile(filePath, findings);
    }
  );
}

async function scanWorkspace(deps: ScanDependencies): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage('SecureLens needs an open workspace to run a workspace scan.');
    return;
  }

  const targets = workspaceFolders.map((folder) => folder.uri.fsPath);

  await runScan(
    {
      kind: 'workspace',
      targets,
      cwd: workspaceFolders[0].uri.fsPath
    },
    deps,
    (findings) => {
      deps.findingsStore.replaceAll(findings);
    }
  );
}

async function runScan(
  request: {
    kind: 'current file' | 'workspace';
    targets: string[];
    cwd: string;
  },
  deps: ScanDependencies,
  onFindings: (findings: Finding[]) => void
): Promise<void> {
  const { outputChannel } = deps;
  outputChannel.show(true);
  outputChannel.appendLine(`[SecureLens] Starting ${request.kind} scan`);
  request.targets.forEach((target) => outputChannel.appendLine(`[SecureLens] Target: ${target}`));

  const statusHandle = vscode.window.setStatusBarMessage('SecureLens scan started...');

  try {
    const semgrepVersion = await deps.semgrepService.ensureAvailable();
    outputChannel.appendLine(`[SecureLens] Semgrep detected: ${semgrepVersion}`);

    const scanResult = await deps.semgrepService.scan({
      targets: request.targets,
      cwd: request.cwd
    });

    if (scanResult.stderr.trim()) {
      outputChannel.appendLine('[SecureLens] Semgrep stderr:');
      outputChannel.appendLine(scanResult.stderr.trim());
    }

    let semgrepFindings: Finding[];
    try {
      semgrepFindings = deps.findingMapper.map(scanResult.rawJson, request.cwd);
    } catch (error) {
      outputChannel.appendLine('[SecureLens] Failed to parse Semgrep JSON output.');
      outputChannel.appendLine(scanResult.rawJson);
      throw new Error(`SecureLens could not parse Semgrep JSON output: ${toErrorMessage(error)}`);
    }

    const regexFindings = await deps.regexRuleService.scanTargets(request.targets);
    const merged = dedupeFindings([...semgrepFindings, ...regexFindings]);
    const enrichedFindings = dedupeFindings(merged.map((finding) => deps.remediationService.enrichFinding(finding)));

    onFindings(enrichedFindings);

    const summary = `SecureLens found ${enrichedFindings.length} issue${enrichedFindings.length === 1 ? '' : 's'}`;
    outputChannel.appendLine(`[SecureLens] ${summary}`);
    outputChannel.appendLine('[SecureLens] SecureLens scan completed');
    vscode.window.setStatusBarMessage(summary, 4000);
    vscode.window.showInformationMessage(summary);
  } catch (error) {
    const message = toErrorMessage(error);
    outputChannel.appendLine(`[SecureLens] Scan failed: ${message}`);

    if (message.toLowerCase().includes('not found on path') || message.toLowerCase().includes('not available on path')) {
      vscode.window.showErrorMessage(
        'SecureLens could not find Semgrep on your PATH. Install it first, for example with "pip install semgrep", then restart VS Code.'
      );
    } else {
      vscode.window.showErrorMessage(`SecureLens scan failed: ${message}`);
    }
  } finally {
    statusHandle.dispose();
    vscode.window.setStatusBarMessage('SecureLens scan completed', 3000);
  }
}

async function openFinding(finding: Finding): Promise<void> {
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.filePath));
  const editor = await vscode.window.showTextDocument(document, { preview: false });
  const range = findingToRange(finding);

  editor.selection = new vscode.Selection(range.start, range.end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const deduped: Finding[] = [];
  const seen = new Set<string>();

  for (const finding of findings) {
    const secretKey = finding.category === 'hardcoded-secret'
      ? `hardcoded-secret|${finding.filePath}|${finding.startLine}|${finding.startCol}`
      : undefined;
    const key = secretKey ?? `${finding.ruleId}|${finding.filePath}|${finding.startLine}|${finding.startCol}|${finding.message}`;

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(finding);
  }

  return deduped;
}

function extractFindingId(arg: unknown): string | undefined {
  if (!arg) {
    return undefined;
  }

  if (typeof arg === 'string') {
    return arg;
  }

  if (typeof arg === 'object') {
    const maybeFinding = arg as { id?: unknown; finding?: { id?: unknown } };

    if (typeof maybeFinding.id === 'string') {
      return maybeFinding.id;
    }

    if (maybeFinding.finding && typeof maybeFinding.finding.id === 'string') {
      return maybeFinding.finding.id;
    }
  }

  return undefined;
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}


