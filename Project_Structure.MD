# NoVuln Enterprise AI SAST Platform - Project Structure

## Overview
**NoVuln** is an AI-powered enterprise Static Application Security Testing (SAST) platform for detecting security vulnerabilities in source code across 8 programming languages. Supports both an **interactive Web Application** and a **standalone DevSecOps CLI pipeline (`novuln`)**.

## Tech Stack
- **Core Engine**: Node.js, Babel AST Parser/Traverse, Regex Heuristics
- **Frontend**: React 18, TailwindCSS, Monaco Editor
- **Backend API**: Node.js, Express.js
- **CLI & Automation**: Commander.js (`novuln` CLI with `--ci` mode)
- **Database**: MongoDB (Optional, with memory cache fallback)
- **AI Layer**: Gemini API / OpenAI API (Enrichment only)
- **Reporting**: PDFKit (PDF reports), Schema Version 1.0 JSON & Summary JSON

---

## Folder Structure

```text
Secure Code Reviewer/
├── backend/                        # Backend Node.js application & CLI engine
│   ├── bin/                        # CLI Executable scripts
│   │   ├── novuln.js               # Primary CLI executable (#!/usr/bin/env node)
│   │   └── scanner.js              # Backward-compatibility CLI executable
│   │
│   ├── src/
│   │   ├── core/                   # Standalone Core SAST Engine
│   │   │   ├── ConfigLoader.js     # Merges config files, CLI options & normalizes paths
│   │   │   ├── DirectoryScanner.js # Recursive file walker & ignore pattern matcher
│   │   │   ├── FindingNormalizer.js# Standardizes raw plugin severities & schemas
│   │   │   ├── GitHelper.js        # Extracts git branch, commit hash & repo metadata
│   │   │   ├── RiskAggregator.js   # Computes summary stats, CVSS & risk scores
│   │   │   └── ScannerEngine.js    # Core SAST orchestrator
│   │   │
│   │   ├── plugins/                # Modular Detection Plugin Architecture
│   │   │   ├── BasePlugin.js       # Abstract base plugin contract
│   │   │   ├── PluginManager.js    # Registers & executes active plugins
│   │   │   ├── ASTPlugin.js        # Babel AST structural injection engine
│   │   │   ├── RegexPlugin.js      # Signature pattern detection engine
│   │   │   ├── SemgrepPlugin.js    # Extensibility stub
│   │   │   └── CodeQLPlugin.js     # Extensibility stub
│   │   │
│   │   ├── ai/                     # AI enrichment service layer
│   │   │   ├── gemini.js           # Gemini API integration
│   │   │   ├── openai.js           # OpenAI GPT integration
│   │   │   ├── prompts.js          # Security prompt templates
│   │   │   └── index.js            # Provider-agnostic AI interface
│   │   │
│   │   ├── reporters/              # Report Generators
│   │   │   ├── ConsoleReporter.js  # Terminal stdout formatter
│   │   │   ├── JSONReporter.js     # Generates report.json & summary.json (v1.0)
│   │   │   └── PDFReporter.js      # Executive PDF document generator
│   │   │
│   │   ├── storage/                # Persistence Abstraction Layer
│   │   │   ├── StorageAdapter.js   # Storage interface
│   │   │   └── MongoStorage.js     # MongoDB adapter with memory cache fallback
│   │   │
│   │   ├── cli/                    # CLI execution layer
│   │   │   ├── index.js            # Commander program setup
│   │   │   └── commands/
│   │   │       └── scanCommand.js  # `novuln scan <path>` action handler
│   │   │
│   │   ├── api/                    # Express Web API layer
│   │   │   ├── controllers/
│   │   │   │   ├── scanController.js   # Web API scan controller
│   │   │   │   └── reportController.js # PDF download controller
│   │   │   ├── middleware/         # Rate limiting, validation & error handlers
│   │   │   └── routes/             # REST endpoint definitions
│   │   │
│   │   ├── services/               # Legacy service references & AST detectors
│   │   │   └── scanner/            # AST visitors & Regex rules
│   │   │
│   │   └── tests/                  # Automated test suites
│   │       ├── test-directory-scanner.js
│   │       ├── test-plugin-manager.js
│   │       └── test-cli-modes.js
│   │
│   ├── .env
│   ├── .env.example                # Environment variables template
│   ├── .gitignore
│   ├── package-lock.json
│   ├── package.json                # Package manifest with CLI bin entry (novuln)
│   └── server.js                   # Express REST API server entrypoint
│
├── frontend/                       # React frontend application
│   ├── public/
│   ├── src/
│   │   ├── components/             # React UI components (Editor, Dashboard, Reports)
│   │   ├── services/               # Frontend API client
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
│
├── docs/                           # Standalone Product Documentation
│   ├── api/
│   │   └── API_SPECIFICATION.md    # REST API endpoints reference
│   ├── architecture/
│   │   └── ARCHITECTURE.md         # Engine architecture & component flow
│   ├── cli/
│   │   └── CLI_USAGE.md            # CLI usage, options, exit codes & workflows
│   ├── config/
│   │   └── CONFIGURATION.md        # Configuration file reference & ignore rules
│   ├── developer/
│   │   └── DEVELOPER_GUIDE.md      # Contributor setup & test runner guide
│   ├── json-schema/
│   │   └── REPORT_SCHEMA.md        # Schema v1.0 specifications for JSON reports
│   └── plugins/
│       └── PLUGIN_DEVELOPMENT.md   # Plugin interface & extension guide
│
├── scanner-manifest.json           # Engine capability manifest
├── scanner.config.json             # Project configuration file
├── .gitignore                      # Monorepo root ignore rules
└── Project_Structure.MD            # Project structure documentation
```

---

## Architecture & Responsibilities

### 1. Standalone Core Engine (`src/core/`)
- **`ScannerEngine.js`**: Core orchestrator. Runs directory scanning, calls `PluginManager`, normalizes findings, aggregates risk metrics, and optionally applies AI enrichment. Operates completely independent of Express and MongoDB.
- **`DirectoryScanner.js`**: Recursively walks folders, honors ignore paths (`node_modules`, `.git`, `dist`, `build`, `coverage`, `vendor`), maps extensions to supported languages, and retains relative file paths (`filePath`).
- **`ConfigLoader.js`**: Validates, normalizes, and merges `scanner.config.json`, default settings, and CLI flag overrides.
- **`FindingNormalizer.js`**: Standardizes severity levels (`Critical`, `High`, `Medium`, `Low`, `Info`) from any plugin output.
- **`RiskAggregator.js`**: Computes summary statistics, CVSS scores, risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MINIMAL`), and CWE/OWASP breakdowns.
- **`GitHelper.js`**: Dynamically extracts Git branch, commit hash, and repository name.

### 2. Plugin Detection System (`src/plugins/`)
- **`PluginManager.js`**: Manages registration, language filtering, and execution of active detection plugins.
- **`ASTPlugin.js`**: Structural injection detector utilizing `@babel/parser` and `@babel/traverse` for JavaScript and TypeScript.
- **`RegexPlugin.js`**: Pattern detector executing signature rules across 8 supported languages.
- **`SemgrepPlugin.js` & `CodeQLPlugin.js`**: Architectural placeholders for future engine adapters.

### 3. Output Reporters (`src/reporters/`)
- **`JSONReporter.js`**: Generates `schemaVersion: "1.0"` output files with `NoVuln` branding:
  - `report.json`: Comprehensive report containing scanner metadata, Git context, summary, findings, CWE/OWASP mappings.
  - `summary.json`: Lightweight summary metrics for instant CI/CD consumption.
- **`ConsoleReporter.js`**: Formats colored NoVuln summary tables and findings lists for terminal stdout.
- **`PDFReporter.js`**: Generates executive PDF reports wrapping PDFKit.

### 4. CLI Execution Modes (`src/cli/`)
- **Developer / Interactive Mode (Default)**: `novuln scan ./src` outputs formatted terminal stdout and **creates zero files on disk**.
- **CI/CD Pipeline Mode (`--ci`)**: `novuln scan ./src --ci` outputs terminal stdout and **automatically generates `report.json` and `summary.json`**.
- **Exit Codes**: `0` for scan completion; `1` for scanner runtime error.

---

## Data Flow

### 1. DevSecOps CLI Pipeline Scan Flow
```text
1. CLI invoked: novuln scan ./src --ci
2. ConfigLoader merges defaults, scanner.config.json & CLI flags
3. DirectoryScanner recursively locates source files in ./src
4. PluginManager executes active plugins (ASTPlugin & RegexPlugin)
5. FindingNormalizer standardizes all raw findings
6. RiskAggregator computes summary stats, CVSS scores & risk levels
7. AIService enriches findings (if enabled & key present)
8. JSONReporter outputs schemaVersion: "1.0" report.json & summary.json with NoVuln branding
9. ConsoleReporter prints terminal summary table
10. Exit code 0 returned
```

### 2. Interactive Web API Scan Flow
```text
1. User submits code snippet via React Frontend (Monaco Editor)
2. Express route POST /api/scan invokes scanController
3. ScannerEngine scans code snippet
4. MongoStorage saves scan document to DB (memory cache fallback)
5. Response returned to frontend containing scanId, summary & vulnerabilities
6. Frontend displays interactive findings, stats dashboard & PDF download option
```

---

## Development & Test Commands

Run the automated test suites from the `backend/` directory:

```bash
cd backend

# Test Directory Scanner & Config Loader
node src/tests/test-directory-scanner.js

# Test Plugin Manager & Finding Normalizer
node src/tests/test-plugin-manager.js

# Test CLI Execution & Report Generators
node src/tests/test-cli-modes.js

# Test Structural AST Detection
node src/services/scanner/test-ast-detection.js

# Test 14 Vulnerability Categories
node src/services/scanner/test-all-categories.js

# Test Multi-Language Scans
node src/services/scanner/test-multi-language.js
```