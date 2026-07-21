const path = require('path');
const BasePlugin = require('./BasePlugin');
const parser = require('../services/scanner/ast/parser');
const { runTraversal } = require('../services/scanner/ast/traversal');
const logger = require('../utils/logger');

/**
 * ASTPlugin
 * Wraps Babel AST parsing and structural visitor traversal for JavaScript and TypeScript.
 */
class ASTPlugin extends BasePlugin {
  constructor() {
    super('AST Structural Engine', 'ast', ['javascript', 'typescript']);
  }

  async scan(code, language, filePath = 'snippet.js') {
    const normLang = (language || 'javascript').toLowerCase();
    if (!this.supportsLanguage(normLang)) {
      return [];
    }

    try {
      const ast = parser.parse(code, filePath);
      const rawFindings = runTraversal(ast, code);

      // Attach file path & source to findings
      return rawFindings.map(f => ({
        ...f,
        filePath,
        source: 'ast'
      }));

    } catch (err) {
      logger.debug(`ASTPlugin parsing error on ${filePath}: ${err.message}`);
      // Return error marker so ScannerEngine can summarize parser failures
      return [{
        __isParserError: true,
        filePath,
        message: err.message
      }];
    }
  }
}

module.exports = ASTPlugin;
