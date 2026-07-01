const { getCalleeName, isDynamic, isStaticLiteral, isUserControlled, isSanitized } = require('../utils/nodeHelpers');
const { buildFinding } = require('../utils/findingBuilder');

/**
 * SSRF AST Detector
 * Checks for outgoing HTTP requests (fetch, axios, http.get, etc.) using dynamic hostnames or URLs.
 */
module.exports = {
  visitor(findings, codeLines) {
    return {
      CallExpression(path) {
        const calleeName = getCalleeName(path.node.callee);
        const ssrfSinks = ['get', 'post', 'request', 'fetch', 'axios'];
        
        const isSink = ssrfSinks.some(sink => 
          calleeName === sink || 
          calleeName.endsWith(`.${sink}`) || 
          calleeName.startsWith('http.') || 
          calleeName.startsWith('https.')
        );

        if (isSink && path.node.arguments.length > 0) {
          const firstArg = path.node.arguments[0];

          // 1. Static Literal check - skip if fully static target URL
          if (isStaticLiteral(firstArg)) {
            return;
          }
          
          if (isDynamic(firstArg)) {
            const userControlled = isUserControlled(firstArg);
            const sanitized = isSanitized(firstArg);

            let confidence = 0.6; // Medium
            let severity = 'High';
            let reason = 'Dynamic URL/hostname passed to HTTP request client';

            if (userControlled && !sanitized) {
              confidence = 1.0; // High
              severity = 'High';
              reason = 'Dynamic user-controlled URL/hostname passed directly to HTTP request client without validation';
            } else if (sanitized) {
              confidence = 0.2; // Low
              severity = 'Medium';
              reason = 'Dynamic URL passed to HTTP request client but sanitized/validated';
            }

            findings.push(buildFinding({
              id: 'JS-SSRF-101',
              type: 'Server-Side Request Forgery (SSRF)',
              severity,
              confidence,
              message: `AST-Server-Side Request Forgery (SSRF): ${reason} (${calleeName})`,
              recommendation: 'Do not allow arbitrary, client-supplied URLs to be fetched directly. Validate and whitelist backend hostnames, or map input keys to static configuration values.',
              cweId: 'CWE-918',
              owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
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
