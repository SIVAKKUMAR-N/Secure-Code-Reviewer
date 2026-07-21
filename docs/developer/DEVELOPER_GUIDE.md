# NoVuln Developer & Contributor Guide

Welcome to the **NoVuln** development guide! This guide covers local project setup, testing procedures, directory organization, and contributing practices.

---

## 1. Project Structure

```text
Secure Code Reviewer/
├── backend/
│   ├── bin/
│   │   ├── novuln.js              # Primary executable CLI launcher
│   │   └── scanner.js             # Legacy CLI launcher alias
│   ├── src/
│   │   ├── core/                  # Core NoVuln SAST engine (ScannerEngine, ConfigLoader, etc.)
│   │   ├── plugins/               # Detection plugin system (AST, Regex, Semgrep, CodeQL)
│   │   ├── ai/                    # Gemini / OpenAI AI enrichment
│   │   ├── reporters/             # JSON, Summary JSON, PDF, and Console reporters
│   │   ├── storage/               # MongoDB & memory cache adapters
│   │   ├── cli/                   # Commander CLI commands & parser
│   │   ├── api/                   # Express REST API controllers & routes
│   │   └── tests/                 # Integration and unit test suites
│   ├── server.js                  # Express API server entrypoint
│   └── package.json               # Backend dependencies & CLI bin configuration
├── frontend/                      # React + TailwindCSS + Monaco Editor UI
├── docs/                          # Project documentation
├── scanner-manifest.json          # Engine capability manifest
└── scanner.config.json            # Project configuration file
```

---

## 2. Local Setup & Installation

### Prerequisites
- Node.js >= 18.0.0
- npm >= 9.0.0
- MongoDB (Optional for Web UI; not required for CLI)

### Installation Steps
```bash
# Clone repository
git clone https://github.com/SIVAKKUMAR-N/Secure-Code-Reviewer.git
cd "Secure Code Reviewer"

# Install backend dependencies & link novuln globally
cd backend
npm install
npm link

# Install frontend dependencies
cd ../frontend
npm install
```

---

## 3. Running Test Suites

Run automated test suites from the `backend/` directory:

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

---

## 4. Development Workflow & Guidelines

1. **Keep Core Engine Independent**: Never import `express` or `mongoose` inside `src/core/` or `src/plugins/`. Keep detection logic pure and reusable.
2. **Normalize Findings**: All plugin findings must pass through `FindingNormalizer.normalize()` before being passed to `RiskAggregator` or `AIService`.
3. **Preserve Backward Compatibility**: Ensure Web API endpoints (`/api/scan`) and React UI components function without breaking changes.
