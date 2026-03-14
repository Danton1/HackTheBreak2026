# SecureLens

SecureLens is a VS Code extension MVP that runs [Semgrep](https://semgrep.dev/) locally and shows findings inside VS Code.

This project is intentionally scoped for a hackathon MVP:

- no AI features
- no backend
- no auth
- no cloud services
- local Semgrep CLI only

## Features

- `SecureLens: Scan Current File`
- `SecureLens: Scan Workspace`
- findings shown as VS Code diagnostics
- raw scan logs shown in the `SecureLens` output channel
- a lightweight `SecureLens Findings` tree view for quick navigation

## Prerequisites

1. Install Node.js 18+ and npm
2. Install Semgrep so `semgrep --version` works in your terminal

Examples:

```bash
pip install semgrep
semgrep --version
```

SecureLens checks Semgrep before every scan and shows a friendly error if it is missing from `PATH`.

## Setup

From the project root:

```bash
npm install
npm run compile
```

## Run the extension

1. Open [C:\Projects\HackTheBreak2026](/C:/Projects/HackTheBreak2026) in VS Code
2. Press `F5`
3. In the Extension Development Host window, open a file or open a folder/workspace
4. Open the Command Palette with `Ctrl+Shift+P` on Windows or `Cmd+Shift+P` on macOS
5. Run one of the SecureLens commands

## Commands

- `SecureLens: Scan Current File`
  - scans the active file only
  - clears old diagnostics for that file
  - reapplies new diagnostics for returned findings
- `SecureLens: Scan Workspace`
  - scans all open workspace folders
  - clears existing SecureLens diagnostics first
  - reapplies diagnostics for all returned findings

## What to expect

After a scan, SecureLens updates:

- the Problems panel
- editor squiggles
- the `SecureLens` output channel
- the `SecureLens Findings` activity bar view

Clicking a finding in the tree view opens the file and jumps to the matching line.

## Demo file

Open [samples/vulnerable-demo.js](/C:/Projects/HackTheBreak2026/samples/vulnerable-demo.js) and run `SecureLens: Scan Current File` for a quick demo.

## Bundled MVP rules

The bundled Semgrep rules are intentionally small and predictable:

- SQL string concatenation
- unsafe `innerHTML`
- dynamic `child_process.exec`
- `eval(...)`
- unsafe Python YAML loading
- unsafe Python pickle deserialization
- obvious hardcoded password-style assignments

Using a bundled rules file keeps the demo stable and avoids noisy `--config auto` results.

## Project structure

```text
src/
  extension.ts
  models/
    Finding.ts
  services/
    DiagnosticsService.ts
    FindingMapper.ts
    SemgrepService.ts
  views/
    FindingsTreeProvider.ts
rules/
  securelens-mvp.yml
samples/
  vulnerable-demo.js
```

## Future extension points

The current design keeps Semgrep execution separate from the VS Code UI so later work can add:

- finding explanation providers
- remediation suggestion providers
- optional AI provider abstractions

The clean next step is a post-scan enrichment layer that reads `Finding` objects and adds extra guidance without changing the scan pipeline.
