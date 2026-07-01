/**
 * AST Parser
 * Parses JavaScript and TypeScript source code into an Abstract Syntax Tree (AST).
 * 
 * Educational Context:
 * 1. Why AST is more accurate than regex:
 *    - Regex scans code line-by-line as flat strings, completely blind to syntax semantics, 
 *      scopes, comments, or dynamic blocks.
 *    - AST parses code into a hierarchical tree structure representing the grammar. This 
 *      allows us to reliably identify specific function calls (e.g. `exec`), verify if their 
 *      arguments are dynamic (e.g. binary string concat or template literals), and ignore matches 
 *      inside strings/comments or variables of the same name defined in different scopes.
 * 
 * 2. Why Regex is still useful:
 *    - Regex is lightweight, extremely fast, and language-agnostic.
 *    - It is ideal for signature-based checks like hardcoded secrets, API tokens, and weak 
 *      hashing algorithms (like MD5) where deep structural context is unnecessary.
 *    - It also serves as a robust fallback if the source code contains syntax errors and fails 
 *      to parse into an AST.
 * 
 * 3. How hybrid scanning improves SAST:
 *    - A hybrid engine provides the "best of both worlds": AST delivers precise structural analysis 
 *      for complex sinks (reducing false positives/negatives), while Regex provides high-speed, 
 *      broad coverage for secrets, configs, and non-AST-supported languages.
 */

const parser = require('@babel/parser');
const logger = require('../../../utils/logger');

/**
 * Parse source code into an AST
 * @param {string} code - Source code text
 * @param {string} filename - Filename (to determine typescript plugins)
 * @returns {Object} Babel AST
 */
function parse(code, filename = 'code.js') {
  const isTypeScript = filename.endsWith('.ts') || filename.endsWith('.tsx');
  
  // Robust plugins configuration to support modern syntax and features
  const plugins = [
    'jsx',
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

  if (isTypeScript) {
    plugins.push('typescript');
  }

  const parseOptions = {
    sourceType: 'module',
    plugins: plugins,
    errorRecovery: true, // Recover from syntax errors where possible
    attachComment: true,
    tokens: true,
    locations: true,
    ranges: true
  };

  try {
    return parser.parse(code, parseOptions);
  } catch (err) {
    logger.debug(`Babel ES module parse failed, retrying in script mode: ${err.message}`);
    try {
      parseOptions.sourceType = 'script';
      return parser.parse(code, parseOptions);
    } catch (innerErr) {
      logger.error(`Babel parse error in script mode: ${innerErr.message}`);
      throw new Error(`Babel parsing failed: ${innerErr.message}`);
    }
  }
}

module.exports = { parse };
