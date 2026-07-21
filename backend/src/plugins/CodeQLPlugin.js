const BasePlugin = require('./BasePlugin');

/**
 * CodeQLPlugin (Architecture placeholder stub for future integration)
 */
class CodeQLPlugin extends BasePlugin {
  constructor() {
    super(
      'CodeQL Engine Adapter',
      'codeql',
      ['javascript', 'typescript', 'python', 'java', 'csharp', 'go'],
      true // isStub = true
    );
  }

  async scan(code, language, filePath = 'snippet.js') {
    // Stub implementation for future CodeQL database CLI integration
    return [];
  }
}

module.exports = CodeQLPlugin;
