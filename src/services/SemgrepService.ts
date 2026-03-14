import * as path from 'path';
import { spawn } from 'child_process';

export interface ScanRequest {
  targets: string[];
  cwd: string;
}

export interface ScanResult {
  rawJson: string;
  stderr: string;
}

interface ProcessResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export class SemgrepService {
  private readonly rulesPath: string;
  private resolvedCommand: string | undefined;

  constructor(extensionPath: string) {
    this.rulesPath = path.join(extensionPath, 'rules', 'securelens-mvp.yml');
  }

  public async ensureAvailable(): Promise<string> {
    const versionResult = await this.runSemgrepCommand(['--version'], process.cwd());

    if (versionResult.code !== 0 || !versionResult.stdout.trim()) {
      throw new Error(versionResult.stderr || 'Semgrep is not available on PATH.');
    }

    return versionResult.stdout.trim();
  }

  public async scan(request: ScanRequest): Promise<ScanResult> {
    const args = [
      'scan',
      '--config',
      this.rulesPath,
      '--json',
      '--quiet',
      ...request.targets
    ];

    const result = await this.runSemgrepCommand(args, request.cwd);

    if (!result.stdout.trim()) {
      throw new Error(result.stderr || 'Semgrep did not return JSON output.');
    }

    return {
      rawJson: result.stdout,
      stderr: result.stderr
    };
  }

  private async runSemgrepCommand(args: string[], cwd: string): Promise<ProcessResult> {
    const command = await this.resolveSemgrepCommand();

    return this.runRawProcess(command, args, cwd);
  }

  private async resolveSemgrepCommand(): Promise<string> {
    if (this.resolvedCommand) {
      return this.resolvedCommand;
    }

    if (process.platform !== 'win32') {
      this.resolvedCommand = 'semgrep';
      return this.resolvedCommand;
    }

    const whereResult = await this.runRawProcess('where', ['semgrep'], process.cwd());
    if (whereResult.code !== 0 || !whereResult.stdout.trim()) {
      throw new Error('SecureLens could not find the Semgrep CLI. Install it so "semgrep --version" works in your terminal.');
    }

    const candidates = whereResult.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    const preferred = candidates.find((candidate) => candidate.toLowerCase().endsWith('.exe')) ?? candidates[0];
    if (!preferred) {
      throw new Error('SecureLens could not find the Semgrep CLI. Install it so "semgrep --version" works in your terminal.');
    }

    this.resolvedCommand = preferred;
    return this.resolvedCommand;
  }

  private runRawProcess(command: string, args: string[], cwd: string): Promise<ProcessResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        cwd,
        shell: false
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (chunk: Buffer | string) => {
        stdout += chunk.toString();
      });

      child.stderr.on('data', (chunk: Buffer | string) => {
        stderr += chunk.toString();
      });

      child.on('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT' || error.code === 'EINVAL') {
          reject(new Error('SecureLens could not find the Semgrep CLI. Install it so "semgrep --version" works in your terminal.'));
          return;
        }

        reject(error);
      });

      child.on('close', (code) => {
        const notFoundMessage = `${stdout}\n${stderr}`.toLowerCase();
        const looksLikeMissingCommand =
          notFoundMessage.includes('not recognized as an internal or external command') ||
          notFoundMessage.includes('command not found');

        if (looksLikeMissingCommand) {
          reject(new Error('SecureLens could not find the Semgrep CLI. Install it so "semgrep --version" works in your terminal.'));
          return;
        }

        resolve({ code, stdout, stderr });
      });
    });
  }
}
