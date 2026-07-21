const BasePlugin = require('./BasePlugin');
const RegexScanner = require('../services/scanner/regex/regexScanner');

/**
 * RegexPlugin
 * Wraps pattern-based signature detection across 8 supported programming languages.
 */
class RegexPlugin extends BasePlugin {
  constructor() {
    super('Regex Heuristic Engine', 'regex', [
      'javascript',
      'typescript',
      'python',
      'java',
      'csharp',
      'ruby',
      'go',
      'php'
    ]);
    this.regexScanner = new RegexScanner();
  }

  async scan(code, language, filePath = 'snippet.js') {
    const rawFindings = await this.regexScanner.scan(code, language);

    return rawFindings.map(f => ({
      ...f,
      filePath: f.filePath || filePath,
      source: f.source || 'regex'
    }));
  }
}

module.exports = RegexPlugin;
