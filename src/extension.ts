import * as path from 'path';
import * as vscode from 'vscode';
import { Finding, findingToRange } from './models/Finding';
import { DiagnosticsService } from './services/DiagnosticsService';
import { FindingMapper } from './services/FindingMapper';
import { SemgrepService } from './services/SemgrepService';
import { FindingsTreeProvider } from './views/FindingsTreeProvider';

export function activate(context: vscode.ExtensionContext): void {
  const outputChannel = vscode.window.createOutputChannel('SecureLens');
  const diagnosticsService = new DiagnosticsService();
  const semgrepService = new SemgrepService(context.extensionPath);
  const findingMapper = new FindingMapper();
  const findingsTreeProvider = new FindingsTreeProvider();

  const treeView = vscode.window.createTreeView('securelens.findings', {
    treeDataProvider: findingsTreeProvider,
    showCollapseAll: false
  });

  context.subscriptions.push(
    outputChannel,
    diagnosticsService,
    findingsTreeProvider,
    treeView,
    vscode.commands.registerCommand('securelens.scanCurrentFile', async () => {
      await scanCurrentFile({
        outputChannel,
        diagnosticsService,
        semgrepService,
        findingMapper,
        findingsTreeProvider
      });
    }),
    vscode.commands.registerCommand('securelens.scanWorkspace', async () => {
      await scanWorkspace({
        outputChannel,
        diagnosticsService,
        semgrepService,
        findingMapper,
        findingsTreeProvider
      });
    }),
    vscode.commands.registerCommand('securelens.openFinding', async (finding: Finding) => {
      await openFinding(finding);
    })
  );
}

export function deactivate(): void {
  // VS Code disposes subscriptions registered during activation.
}

interface ScanDependencies {
  outputChannel: vscode.OutputChannel;
  diagnosticsService: DiagnosticsService;
  semgrepService: SemgrepService;
  findingMapper: FindingMapper;
  findingsTreeProvider: FindingsTreeProvider;
}

async function scanCurrentFile(deps: ScanDependencies): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor || editor.document.uri.scheme !== 'file') {
    vscode.window.showWarningMessage('SecureLens needs an open file to scan the current file.');
    return;
  }

  const fileUri = editor.document.uri;
  const filePath = fileUri.fsPath;

  deps.diagnosticsService.clearFile(fileUri);
  deps.findingsTreeProvider.setFindings([]);

  await runScan(
    {
      kind: 'current file',
      targets: [filePath],
      cwd: path.dirname(filePath)
    },
    deps
  );
}

async function scanWorkspace(deps: ScanDependencies): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage('SecureLens needs an open workspace to run a workspace scan.');
    return;
  }

  const targets = workspaceFolders.map((folder) => folder.uri.fsPath);

  deps.diagnosticsService.clearAll();
  deps.findingsTreeProvider.setFindings([]);

  await runScan(
    {
      kind: 'workspace',
      targets,
      cwd: workspaceFolders[0].uri.fsPath
    },
    deps
  );
}

async function runScan(
  request: {
    kind: 'current file' | 'workspace';
    targets: string[];
    cwd: string;
  },
  deps: ScanDependencies
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

    let findings: Finding[];
    try {
      findings = deps.findingMapper.map(scanResult.rawJson, request.cwd);
    } catch (error) {
      outputChannel.appendLine('[SecureLens] Failed to parse Semgrep JSON output.');
      outputChannel.appendLine(scanResult.rawJson);
      throw new Error(`SecureLens could not parse Semgrep JSON output: ${toErrorMessage(error)}`);
    }

    deps.diagnosticsService.applyFindings(findings);
    deps.findingsTreeProvider.setFindings(findings);

    const summary = `SecureLens found ${findings.length} issue${findings.length === 1 ? '' : 's'}`;
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

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
