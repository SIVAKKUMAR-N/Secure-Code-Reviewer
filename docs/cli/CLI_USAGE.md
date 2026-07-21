# NoVuln CLI Usage & Installation Guide

**NoVuln** behaves like native security tools (`git`, `trivy`, `semgrep`, `nmap`, `eslint`), allowing you to execute `novuln` natively from any directory on Windows (PowerShell/CMD), Linux, and macOS.

---

## Installation & Uninstallation

### 1. Development Installation (`npm link`)
To register the `novuln` command globally on your system during local development:

```bash
cd backend
npm link
```

### 2. Production Installation (`npm install -g`)
```bash
npm install -g novuln-backend
```

### 3. Uninstallation
To remove the `novuln` executable from your global PATH:

```bash
# Unlink local development command
cd backend
npm unlink

# Or uninstall global npm package
npm uninstall -g novuln-backend
```

---

## Developer vs. CI/CD Pipeline Workflows

NoVuln automatically detects the current working directory (`process.cwd()`) as the scan target:

### 1. Developer / Interactive Mode (Default)
When run locally, `novuln` prints results directly to stdout and **creates zero files on disk**:

```bash
novuln scan .
novuln scan ./src
```
* Output: Formatted terminal tables & findings list.
* Output Files: None.

### 2. CI/CD Pipeline Mode (`--ci`)
When running inside automated CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins), pass `--ci`. NoVuln automatically exports `report.json` and `summary.json`:

```bash
novuln scan . --ci
```
* Output: Terminal stdout summary AND auto-generated `report.json` & `summary.json`.

---

## Command Reference & Flags

| Command / Option | Description | Example |
|---|---|---|
| `novuln --version` | Output NoVuln version | `novuln --version` |
| `novuln --help` | Display CLI help menu | `novuln --help` |
| `novuln scan <path>` | Scan directory or file recursively | `novuln scan .` |
| `--ci` | Enable CI mode (auto-exports `report.json` & `summary.json`) | `novuln scan . --ci` |
| `-c, --config <path>` | Custom `scanner.config.json` path | `novuln scan . -c my-config.json` |
| `-j, --json <path>` | Explicitly export full JSON report | `novuln scan . -j report.json` |
| `-s, --summary <path>`| Explicitly export summary JSON | `novuln scan . -s summary.json` |
| `-p, --pdf <path>` | Explicitly export PDF executive report | `novuln scan . -p report.pdf` |
| `--store` | Persist report to MongoDB database | `novuln scan . --store` |
| `--no-ai` | Disable AI enrichment for fast offline scans | `novuln scan . --no-ai` |

---

## Exit Codes

- `0`: Scan completed successfully (findings generated, reports exported if requested).
- `1`: NoVuln runtime error (e.g. target path missing, unhandled crash).
