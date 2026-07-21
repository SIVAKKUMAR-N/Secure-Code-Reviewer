const path = require('path');
const parser = require('@babel/parser');
const logger = require('../../../utils/logger');

/**
 * Parse source code into an AST with language-appropriate Babel plugins
 * @param {string} code - Source code text
 * @param {string} filename - Filename (used to determine TypeScript and JSX plugins)
 * @returns {Object} Babel AST
 */
function parse(code, filename = 'code.js') {
  const ext = path.extname(filename).toLowerCase();
  const isTs = ext === '.ts' || ext === '.tsx' || filename.endsWith('.ts') || filename.endsWith('.tsx');
  const isJsx = ext === '.jsx' || ext === '.tsx' || filename.endsWith('.jsx') || filename.endsWith('.tsx');

  const plugins = [
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'decorators-legacy',
    'doExpressions',
    'dynamicImport',
    'exportDefaultFrom',
    'exportNamespaceFrom',
    'functionBind',
    'functionSent',
    'importMeta',
    'logicalAssignment',
    'nullishCoalescingOperator',
    'numericSeparator',
    'objectRestSpread',
    'optionalChaining',
    'optionalCatchBinding',
    'partialApplication',
    'privateIn',
    'throwExpressions',
    'topLevelAwait'
  ];

  if (isTs) {
    plugins.push('typescript');
  }

  // Include JSX plugin for .jsx and .tsx, or non-TS files (.js)
  if (isJsx || !isTs) {
    plugins.push('jsx');
  }

  const parseOptions = {
    sourceType: 'module',
    plugins,
    errorRecovery: true, // Recover from minor syntax errors where possible
    attachComment: true,
    tokens: true,
    locations: true,
    ranges: true
  };

  try {
    return parser.parse(code, parseOptions);
  } catch (err) {
    logger.debug(`Babel module parse failed for ${filename}, retrying in script mode: ${err.message}`);
    try {
      parseOptions.sourceType = 'script';
      return parser.parse(code, parseOptions);
    } catch (innerErr) {
      logger.debug(`Babel parsing failed for ${filename}: ${innerErr.message}`);
      throw new Error(`Babel parsing failed in ${filename}: ${innerErr.message}`);
    }
  }
}

module.exports = { parse };
