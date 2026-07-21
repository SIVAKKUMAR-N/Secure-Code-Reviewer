# NoVuln — Enterprise AI SAST Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/SIVAKKUMAR-N/NoVuln)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-brightgreen.svg)](https://nodejs.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)]()

**NoVuln** is an enterprise-inspired **AI-assisted Static Application Security Testing (SAST)** platform that combines **AST analysis** and **Regex-based detection** to identify security vulnerabilities in source code.

NoVuln provides:

- 🖥️ Standalone CLI (`novuln`)
- 🌐 React-based Web Dashboard
- 🤖 Optional AI-assisted vulnerability explanations
- 📄 Professional JSON & PDF reports
- ⚙️ DevSecOps / CI integration

---

# Features

- Hybrid AST + Regex detection engine
- Repository-wide scanning
- Multi-language support
- Optional AI enrichment (Gemini/OpenAI)
- Professional CLI
- Interactive Web Dashboard
- JSON reports
- Executive PDF reports
- Machine-readable summary reports
- Plugin-based architecture
- CI/CD friendly
- Configurable scanning via `scanner.config.json`
- Enterprise-style modular architecture

---

# Supported Languages

- JavaScript
- TypeScript
- Python
- Java
- C#
- Go
- Ruby
- PHP

---

# Architecture

```
Target Repository
        │
        ▼
 Directory Scanner
        │
        ▼
 Plugin Manager
   ├── AST Plugin
   └── Regex Plugin
        │
        ▼
 Finding Normalizer
        │
        ▼
 Risk Aggregator
        │
        ▼
 AI Enrichment (Optional)
        │
        ▼
 Report Generator
   ├── report.json
   ├── summary.json
   └── PDF Report
        │
        ▼
 CLI / Web Dashboard
```

---

# Installation

## Install from Source (Current)

```bash
git clone https://github.com/SIVAKKUMAR-N/NoVuln.git

cd NoVuln/backend

npm install

npm link
```

Verify installation:

```bash
novuln doctor
```

---

## npm Installation (Coming Soon)

```bash
npm install -g novuln
```

> This command will be available after NoVuln is published to npm.

---

# Quick Start

Scan current project

```bash
novuln scan .
```

CI Mode

```bash
novuln scan . --ci
```

Verbose mode

```bash
novuln scan ./src --verbose
```

Generate PDF

```bash
novuln scan . --pdf security-report.pdf
```

Offline Scan

```bash
novuln scan . --no-ai
```

Environment Check

```bash
novuln doctor
```

---

# scanner.config.json

Create a `scanner.config.json` file in the project root.

```json
{
  "schemaVersion": "1.0",
  "ignore": [
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    "vendor",
    ".env"
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
  "ai": true
}
```

---

# Reports

NoVuln generates:

### report.json

Contains

- Vulnerabilities
- Severity
- CWE
- OWASP
- File Path
- Line Number
- Code Snippet
- AI Explanation
- Secure Fix

### summary.json

Contains

- Total Findings
- Severity Breakdown
- Risk Score
- Risk Level
- Scan Duration

### PDF Report

Professional executive report suitable for management or audit documentation.

---

# AI Enrichment

AI is **optional**.

Security detection is performed entirely by the local AST and Regex engines.

When configured, AI enhances findings by providing:

- Vulnerability explanation
- Security impact
- Example attack scenario
- Recommended secure fix

If no API key is configured, NoVuln continues scanning normally.

---

# Web Application

Start Backend

```bash
cd backend

npm run dev
```

Backend

```
http://localhost:5000
```

Start Frontend

```bash
cd frontend

npm run dev
```

Frontend

```
http://localhost:3000
```

---

# CLI Examples

Developer Scan

```bash
novuln scan .
```

Repository Scan

```bash
novuln scan ./backend
```

CI/CD Scan

```bash
novuln scan . --ci
```

Generate PDF

```bash
novuln scan . --pdf report.pdf
```

Doctor

```bash
novuln doctor
```

---

# Roadmap

- [ ] Publish NoVuln to npm
- [ ] GitHub Action
- [ ] SARIF Output
- [ ] Semgrep Plugin
- [ ] CodeQL Plugin
- [ ] Custom Rule Engine
- [ ] VS Code Extension
- [ ] Docker Image
- [ ] GitLab CI Integration

---

# Project Structure

```
backend/
│
├── bin/
├── src/
│   ├── core/
│   ├── plugins/
│   ├── ai/
│   ├── reporters/
│   ├── storage/
│   ├── cli/
│   ├── api/
│   └── utils/
│
├── tests/
├── package.json
└── scanner-manifest.json
```

---

# License

This project is licensed under the MIT License.

---

# Author

**SIVAKKUMAR N**

Cybersecurity Student | Application Security | DevSecOps | Secure Software Engineering

GitHub: https://github.com/SIVAKKUMAR-N