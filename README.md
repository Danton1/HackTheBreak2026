# 🛡️🔍 SecureLens

SecureLens is a VS Code security assistant that goes beyond a plain scanner.

It combines the power of local [Semgrep](https://semgrep.dev/) analysis with focused built-in regex checks, human-friendly explanations, actionable remediations, and practical quick fixes.  
The result: developers get not only *what failed*, but also *why it matters* and *what to do next*.

## Why SecureLens

SecureLens is designed to help teams ship safer code faster, especially when code changes are moving quickly.

Key differentiators:

- **Hybrid detection engine**: Semgrep + built-in regex + user-defined custom regex rules
- **Humanized security guidance**: each finding includes clear explanation and detailed next steps
- **Action-oriented UX**: quick fixes, focused suggestions, and clickable findings
- **Local-first workflow**: scans run locally with Semgrep CLI (no backend required)
- **Configurable behavior**: control auto-rescan on fixes and define your own regex security checks

## Features

- Scan commands:
  - `SecureLens: Scan Current File`
  - `SecureLens: Scan Workspace`
- Findings surfaced in:
  - editor squiggles and Problems panel (via VS Code diagnostics)
  - `SecureLens` output channel for scan logs/debug info
  - Activity Bar views:
    - **Actions**
    - **Findings**
    - **Suggestions**
- Click a finding to open the file at the exact range
- Dismiss individual findings during the session
- Starter quick fixes:
  - hardcoded secret -> `process.env.*` (+ `.env` and `.gitignore` support)
  - `innerHTML` -> `textContent`
  - eval guidance action
- Optional automatic rescan after quick fix
- User-defined custom regex rules from settings

## Prerequisites

1. Node.js 18+
2. VS Code 1.90+
3. Python 3.10+ (for Semgrep CLI)
4. Semgrep installed and available on `PATH`

Example install:

```bash
pip install semgrep
semgrep --version
```

SecureLens checks Semgrep availability before each scan and shows a friendly error when missing.

## Install and run (development)

From the project root:

```bash
npm install
npm run compile
```

Then launch Extension Development Host:

1. Open the project in VS Code
2. Press `F5` (or Run > Start Debugging)
3. In the new VS Code window, open a file/workspace and run SecureLens commands

## Commands

- `SecureLens: Scan Current File`
  - scans the active file
  - refreshes findings for that file
- `SecureLens: Scan Workspace`
  - scans open workspace folder(s)
  - refreshes all findings
- `SecureLens: Open Finding`
  - navigates to the finding location
- `SecureLens: Dismiss Finding`
  - removes the finding from current session views/diagnostics

## Supported issue categories

SecureLens currently includes detection and guidance for common categories, including:

- `hardcoded-secret`
- `sql-injection`
- `xss-innerhtml`
- `command-injection`
- `insecure-eval`
- `secret-exposure`
- `generic-security-warning` fallback

## Settings

SecureLens contributes these settings:

### `securelens.rerunScanOnQuickFix`

- Type: `boolean`
- Default: `true`
- Description: rerun SecureLens scan automatically after applying a SecureLens quick fix.

Behavior:

- `true`: quick fix applies, then SecureLens triggers `Scan Current File`
- `false`: quick fix applies without automatic rescan

### `securelens.customRegexRules`

- Type: `array`
- Default: `[]`
- Purpose: add your own regex-based security checks alongside built-in checks

Each rule object supports:

- `id` (string, required)
- `name` (string, required)
- `pattern` (string, required, regex without `/.../`)
- `message` (string, required)
- `flags` (string, optional, example `i`, `im`)
- `severity` (`ERROR` | `WARNING` | `INFO`, optional)
- `category` (string, optional)
- `explanation` (string, optional)
- `detailedSolution` (string, optional)
- `fileExtensions` (string[], optional; example `[".js", ".ts"]`)
- `source` (string, optional; default `custom-regex`)

Notes:

- Invalid regex patterns are skipped safely.
- Malformed custom rules do not crash the extension.
- Global matching is enforced automatically so all matches are collected.
- Custom findings flow through the same findings/diagnostics/remediation pipeline.

## Custom rule examples

Add this to your VS Code `settings.json`:

```json
{
  "securelens.customRegexRules": [
    {
      "id": "custom.no-console-auth",
      "name": "Auth header logged",
      "pattern": "console\\.log\\([^\\n]*authorization",
      "flags": "i",
      "severity": "WARNING",
      "category": "secret-exposure",
      "message": "Authorization-related value may be logged",
      "explanation": "Logging authorization data can leak credentials into logs.",
      "detailedSolution": "Remove or mask sensitive values before logging.",
      "fileExtensions": [".js", ".ts", ".tsx", ".jsx"]
    },
    {
      "id": "custom.sql-select-concat",
      "name": "Raw SELECT concatenation",
      "pattern": "SELECT[\\s\\S]*\\+\\s*[a-zA-Z_][a-zA-Z0-9_]*",
      "flags": "i",
      "severity": "WARNING",
      "category": "sql-injection",
      "message": "SQL query appears to be concatenated with dynamic input",
      "explanation": "Concatenating dynamic values into SQL can enable injection attacks.",
      "detailedSolution": "Use parameterized queries or prepared statements."
    }
  ]
}
```

## Quick fix behavior for hardcoded secrets

When SecureLens applies the hardcoded secret quick fix:

- code is updated to `process.env.<NAME>`
- `.env` is created if needed
- missing variable entries are appended safely
- existing variable names are reused only when values match
- collisions get deterministic suffixes (for example `_1`, `_2`)
- `.gitignore` is updated to include `.env` when needed

## Privacy and execution model

SecureLens is local-first:

- scans are executed locally for safety and speed
- Semgrep CLI runs on your machine
- no backend or cloud service is required for scanning/remediation, keeping your code private

## Troubleshooting

- **Semgrep not found**
  - install Semgrep and ensure `semgrep --version` works in terminal used by VS Code
- **No findings after scan**
  - confirm file type is supported and code contains a matching pattern
  - check `SecureLens` output channel for logs
- **Custom rules not triggering**
  - verify regex pattern syntax
  - ensure `fileExtensions` includes the file extension (for example `.ts`)
  - remove escaping mistakes and test with simpler patterns first

## Developer

Created and maintained by [**Danton Soares**](https://www.dantonsoares.com/).
