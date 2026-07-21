# NoVuln Configuration Guide

**NoVuln** supports project-level configuration files (`scanner.config.json`) and capability manifests (`scanner-manifest.json`).

---

## 1. Project Configuration File (`scanner.config.json`)

Place `scanner.config.json` in the root of your project directory (or specify a custom path via `novuln scan ./src -c ./custom-config.json`).

```json
{
  "$schema": "https://json.schemastore.org/scanner.config.json",
  "schemaVersion": "1.0",
  "ignore": [
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    "vendor",
    ".env",
    ".vscode",
    ".idea",
    "temp",
    "tmp"
  ],
  "languages": [
    "javascript",
    "typescript",
    "python",
    "java",
    "csharp",
    "ruby",
    "go",
    "php"
  ],
  "ai": true,
  "output": {
    "json": "report.json",
    "summary": "summary.json",
    "pdf": null
  }
}
```

### Options Reference

| Property | Type | Description | Default |
|---|---|---|---|
| `schemaVersion` | `string` | Configuration schema version | `"1.0"` |
| `ignore` | `Array<string>` | List of folder names or relative paths to ignore | `["node_modules", ".git", "dist", ...]` |
| `languages` | `Array<string>` | List of target programming languages | `["javascript", "typescript", ...]` |
| `ai` | `boolean` | Enable or disable AI explanation enrichment | `true` |
| `output.json` | `string` | Default file path for full JSON report | `"report.json"` |
| `output.summary` | `string` | Default file path for lightweight summary JSON | `"summary.json"` |
| `output.pdf` | `string|null` | Default file path for PDF executive report | `null` |

---

## 2. Ignore Path Normalization

The NoVuln configuration loader automatically normalizes ignore entries across OS platforms (Windows, Linux, macOS).

* All of these configurations resolve identically:
  - `node_modules`
  - `node_modules/`
  - `.\node_modules\`
  - `./node_modules/`

---

## 3. Capability Manifest (`scanner-manifest.json`)

The capability manifest describes active detection plugins, architectural stubs, and supported language features:

```json
{
  "scanner": "NoVuln",
  "edition": "Enterprise AI SAST Platform",
  "version": "2.0.0",
  "schemaVersion": "1.0",
  "description": "Enterprise AI-powered SAST Platform with repository scanning, CLI, Web UI, AI-assisted analysis, reporting, and DevSecOps integration.",
  "activePlugins": [
    "ASTPlugin",
    "RegexPlugin"
  ],
  "availableStubs": [
    "SemgrepPlugin",
    "CodeQLPlugin"
  ],
  "supportedLanguages": [
    "javascript",
    "typescript",
    "python",
    "java",
    "csharp",
    "ruby",
    "go",
    "php"
  ],
  "capabilities": {
    "astParsing": true,
    "regexHeuristics": true,
    "aiEnrichment": true,
    "pdfReporting": true,
    "jsonReporting": true,
    "directoryScanning": true
  }
}
```
