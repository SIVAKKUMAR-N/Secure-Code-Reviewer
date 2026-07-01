/**
 * AST Traversal Orchestrator
 * Consolidates all AST detectors into a single-pass AST traversal to maximize performance.
 */

const traverse = require('@babel/traverse').default || require('@babel/traverse');
const commandInjection = require('./detectors/commandInjection');
const sqlInjection = require('./detectors/sqlInjection');
const dangerousEval = require('./detectors/dangerousEval');
const xss = require('./detectors/xss');
const ssrf = require('./detectors/ssrf');
const pathTraversal = require('./detectors/pathTraversal');

/**
 * Traverses an AST and runs all registered AST detectors.
 * @param {Object} ast - Babel AST object
 * @param {string} code - Original source code
 * @returns {Array} List of detected vulnerabilities
 */
function runTraversal(ast, code) {
  const codeLines = code.split('\n');
  const findings = [];

  // Register all 6 AST detectors
  const detectors = [
    commandInjection,
    sqlInjection,
    dangerousEval,
    xss,
    ssrf,
    pathTraversal
  ];

  // Combined visitor tree object
  const combinedVisitor = {};

  // Merge visitors from all detectors dynamically
  detectors.forEach(detector => {
    const visitorObj = detector.visitor(findings, codeLines);
    
    Object.keys(visitorObj).forEach(nodeType => {
      if (!combinedVisitor[nodeType]) {
        // If node type doesn't have a visitor registered yet, register this one
        combinedVisitor[nodeType] = function (path) {
          visitorObj[nodeType](path);
        };
      } else {
        // Compose multiple visitor functions sequentially for a single node type
        const existingVisitor = combinedVisitor[nodeType];
        combinedVisitor[nodeType] = function (path) {
          existingVisitor(path);
          visitorObj[nodeType](path);
        };
      }
    });
  });

  // Traverse the AST tree using our composed visitors
  traverse(ast, combinedVisitor);

  return findings;
}

module.exports = { runTraversal };
