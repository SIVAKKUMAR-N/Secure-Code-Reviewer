const BasePlugin = require('./BasePlugin');

/**
 * SemgrepPlugin (Architecture placeholder stub for future integration)
 */
class SemgrepPlugin extends BasePlugin {
  constructor() {
    super(
      'Semgrep Engine Adapter',
      'semgrep',
      ['javascript', 'typescript', 'python', 'java', 'go'],
      true // isStub = true
    );
  }

  async scan(code, language, filePath = 'snippet.js') {
    // Stub implementation for future Semgrep CLI integration
    return [];
  }
}

module.exports = SemgrepPlugin;
