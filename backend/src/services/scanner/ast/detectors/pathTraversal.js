const { getCalleeName, isDynamic, isStaticLiteral, isUserControlled, isSanitized } = require('../utils/nodeHelpers');
const { buildFinding } = require('../utils/findingBuilder');

/**
 * Path Traversal AST Detector
 * Checks for file system access methods (fs.readFile, fs.createReadStream, open, etc.) with dynamic arguments.
 */
module.exports = {
  visitor(findings, codeLines) {
    return {
      CallExpression(path) {
        const calleeName = getCalleeName(path.node.callee);
        const fsSinks = [
          'readFile', 'readFileSync', 'createReadStream',
          'writeFile', 'writeFileSync', 'createWriteStream',
          'open', 'openSync', 'require'
        ];
        
        const isSink = fsSinks.some(sink => 
          calleeName === sink || calleeName.endsWith(`.${sink}`)
        );

        if (isSink && path.node.arguments.length > 0) {
          const firstArg = path.node.arguments[0];
          
          // Require is common and only traversal if it's dynamic
          if (calleeName === 'require' && !isDynamic(firstArg)) {
            return; // Normal static require
          }

          // 1. Static literal check - skip if static path
          if (isStaticLiteral(firstArg)) {
            return;
          }

          // 2. Sanitization check - suppress if path cleaners are used (e.g. path.basename)
          if (isSanitized(firstArg)) {
            return;
          }
          
          if (isDynamic(firstArg)) {
            const userControlled = isUserControlled(firstArg);

            let confidence = 0.6; // Medium
            let severity = 'High';
            let reason = 'Dynamic path construction passed to filesystem operation sink';

            if (userControlled) {
              confidence = 1.0; // High
              severity = 'High';
              reason = 'Dynamic user-controlled input passed directly to filesystem operation sink without sanitization';
            }

            findings.push(buildFinding({
              id: 'JS-TRAV-101',
              type: 'Path Traversal',
              severity,
              confidence,
              message: `AST-Path Traversal: ${reason} (${calleeName})`,
              recommendation: 'Sanitize file paths using path.basename() or map user input to a predefined dictionary of safe files. Avoid path concatenation.',
              cweId: 'CWE-22',
              owaspCategory: 'A01:2021 - Broken Access Control',
              node: path.node,
              codeLines,
              sink: calleeName,
              reason
            }));
          }
        }
      }
    };
  }
};
