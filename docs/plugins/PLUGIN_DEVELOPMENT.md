# Plugin Architecture & Development Guide

The AI Secure Code Scanner uses a plugin architecture managed by `PluginManager`. All detection logic is modularized into plugins subclassing `BasePlugin`.

---

## 1. Plugin Architecture Overview

```text
               +----------------------------------+
               |          PluginManager           |
               +----------------------------------+
                                |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
+---------------+       +---------------+       +---------------+
|   ASTPlugin   |       |  RegexPlugin  |       | SemgrepPlugin |
| (Active Engine)|       | (Active Engine)|       | (Disabled Stub)|
+---------------+       +---------------+       +---------------+
        |                       |                       |
        +-----------------------+-----------------------+
                                | Raw Findings
                                v
               +----------------------------------+
               |        FindingNormalizer         |
               +----------------------------------+
                                | Standardized Findings
                                v
               +----------------------------------+
               |          RiskAggregator          |
               +----------------------------------+
```

---

## 2. Active Plugins vs. Architectural Stubs

Plugins specify their active vs. stub status in `BasePlugin`:

- **Active Plugins** (`enabled = true`, `isStub = false`): Executed during scans (e.g. `ASTPlugin`, `RegexPlugin`).
- **Architectural Stubs** (`enabled = false`, `isStub = true`): Architectural placeholders for future tools (e.g. `SemgrepPlugin`, `CodeQLPlugin`). Stubs are registered for capability discovery but skipped during execution.

---

## 3. Developing Custom Plugins

Inherit from `BasePlugin` and implement `scan(code, language, filePath)`:

```javascript
const BasePlugin = require('./BasePlugin');

class CustomRulePlugin extends BasePlugin {
  constructor() {
    super(
      'Custom Security Plugin', // Name
      'custom',                 // Type
      ['javascript', 'python'], // Supported languages
      false                     // isStub (false = active)
    );
  }

  /**
   * Scan implementation
   * @param {string} code - Target source code
   * @param {string} language - Target language
   * @param {string} filePath - Relative file path
   * @returns {Promise<Array<Object>>} Raw findings
   */
  async scan(code, language, filePath = 'snippet.js') {
    const findings = [];

    // Custom analysis...
    if (code.includes('SECRET_KEY')) {
      findings.push({
        id: 'CUSTOM-SEC-001',
        type: 'Hardcoded Secret',
        severity: 'High',
        line: 1,
        message: 'Hardcoded SECRET_KEY identifier detected',
        filePath
      });
    }

    return findings;
  }
}

module.exports = CustomRulePlugin;
```

---

## 4. Registering Custom Plugins

Register custom plugins with `PluginManager`:

```javascript
const PluginManager = require('./src/plugins/PluginManager');
const CustomRulePlugin = require('./CustomRulePlugin');

const manager = new PluginManager();
manager.register(new CustomRulePlugin());
```
