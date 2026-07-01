const { getCalleeName, isDynamic, isStaticLiteral, isUserControlled, isSanitized } = require('../utils/nodeHelpers');
const { buildFinding } = require('../utils/findingBuilder');

/**
 * Dangerous Eval AST Detector
 * Checks for eval() or window.eval() invocations executing dynamic arguments.
 */
module.exports = {
  visitor(findings, codeLines) {
    return {
      CallExpression(path) {
        const calleeName = getCalleeName(path.node.callee);
        const isSink = (calleeName === 'eval' || calleeName === 'window.eval');

        if (isSink && path.node.arguments.length > 0) {
          const firstArg = path.node.arguments[0];

          // 1. Static literal check
          if (isStaticLiteral(firstArg)) {
            return;
          }
          
          if (isDynamic(firstArg)) {
            const userControlled = isUserControlled(firstArg);
            const sanitized = isSanitized(firstArg);

            let confidence = 0.6; // Medium
            let severity = 'Critical';
            let reason = 'Dynamic code evaluation passed to eval() sink';

            if (userControlled && !sanitized) {
              confidence = 1.0; // High
              severity = 'Critical';
              reason = 'Dynamic user-controlled input passed directly to dangerous eval() sink';
            } else if (sanitized) {
              confidence = 0.2; // Low
              severity = 'Medium';
              reason = 'Dynamic code execution via eval() containing sanitized/parsed input';
            }

            findings.push(buildFinding({
              id: 'JS-EVAL-101',
              type: 'Dangerous Eval',
              severity,
              confidence,
              message: `AST-Dangerous Eval: ${reason} (${calleeName})`,
              recommendation: 'Do not parse or execute dynamic strings as JavaScript code. Use structured data formats like JSON, configuration maps, or standard API functions.',
              cweId: 'CWE-95',
              owaspCategory: 'A03:2021 - Injection',
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
