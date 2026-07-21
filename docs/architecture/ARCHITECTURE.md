# NoVuln System Architecture Specification

**NoVuln** is an enterprise-grade AI Static Application Security Testing (SAST) platform. It is engineered with a modular, decoupled architecture supporting both an **interactive Web UI** and a **headless DevSecOps CLI (`novuln`)**.

---

## High-Level Component Flow

```text
                               +-----------------------------+
                               |     NoVuln CLI / Web UI     |
                               +-----------------------------+
                                              |
                                              v
                               +-----------------------------+
                               |        ScannerEngine        |
                               +-----------------------------+
                                              |
        +-------------------------------------+-------------------------------------+
        |                                     |                                     |
        v                                     v                                     v
+-----------------------+           +-----------------------+           +-----------------------+
|   DirectoryScanner    |           |     PluginManager     |           |     ConfigLoader      |
| (File Tree Walker)    |           | (Active Detection)    |           | (Ignore & Language)   |
+-----------------------+           +-----------------------+           +-----------------------+
                                              |
                                              v
                               +-----------------------------+
                               |      FindingNormalizer      |
                               |  (Schema & Severity Map)    |
                               +-----------------------------+
                                              |
                                              v
                               +-----------------------------+
                               |       RiskAggregator        |
                               |  (CVSS, Risk Score & Stats) |
                               +-----------------------------+
                                              |
                                              v
                               +-----------------------------+
                               |         AIService           |
                               | (Explanation & Remediation) |
                               +-----------------------------+
                                              |
                                              v
                               +-----------------------------+
                               |          Reporters          |
                               |  (JSON, Summary JSON, PDF)  |
                               +-----------------------------+
```

---

## Core Component Responsibilities

1. **`ScannerEngine`**: Orchestrates target location, config loading, plugin execution, normalization, risk aggregation, AI enrichment, and report output.
2. **`DirectoryScanner`**: Recursively scans file directories while applying ignore patterns (`node_modules`, `.git`, `dist`, `build`, `coverage`, `vendor`). Retains relative paths (`filePath`).
3. **`PluginManager`**: Discovers, registers, and executes active functional detection plugins (`ASTPlugin`, `RegexPlugin`). Filters out stub plugins (`SemgrepPlugin`, `CodeQLPlugin`).
4. **`FindingNormalizer`**: Maps raw plugin outputs to standard enterprise severity levels (`Critical`, `High`, `Medium`, `Low`, `Info`).
5. **`RiskAggregator`**: Calculates overall risk scores (0-100), risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MINIMAL`), and maps findings to OWASP Top 10 and CWE IDs.
6. **`AIService`**: Provider-agnostic AI layer (Gemini / OpenAI) providing vulnerability explanations, exploit demonstrations, and secure code fixes.
