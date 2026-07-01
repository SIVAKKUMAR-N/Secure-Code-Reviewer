const { getCalleeName, isDynamic, isStaticLiteral, isUserControlled, isSanitized } = require('../utils/nodeHelpers');
const { buildFinding } = require('../utils/findingBuilder');

/**
 * XSS AST Detector
 * Checks for:
 * 1. DOM / Output stream write sinks (document.write, res.write, res.send, etc.) receiving dynamic variables.
 * 2. Assignment to element.innerHTML / element.outerHTML using dynamic variables.
 * 3. React dangerouslySetInnerHTML attribute usage.
 */
module.exports = {
  visitor(findings, codeLines) {
    return {
      // 1. Call Expressions (e.g. document.write, res.send, res.write, element.html)
      CallExpression(path) {
        const calleeName = getCalleeName(path.node.callee);
        const xssCallSinks = ['write', 'writeln', 'send', 'html', 'append'];
        
        const isSink = xssCallSinks.some(sink => 
          calleeName === sink || calleeName.endsWith(`.${sink}`)
        );

        if (isSink && path.node.arguments.length > 0) {
          const firstArg = path.node.arguments[0];

          // Skip if static literal
          if (isStaticLiteral(firstArg)) {
            return;
          }
          
          if (isDynamic(firstArg)) {
            const userControlled = isUserControlled(firstArg);
            const sanitized = isSanitized(firstArg);

            // Skip if sanitized
            if (sanitized) {
              return;
            }

            let confidence = 0.6; // Medium
            let severity = 'High';
            let reason = 'Dynamic value written to response/DOM output stream';

            if (userControlled) {
              confidence = 1.0; // High
              severity = 'High';
              reason = 'Dynamic user-controlled input written directly to response/DOM output stream without sanitization';
            }

            findings.push(buildFinding({
              id: 'JS-XSS-101',
              type: 'Cross-Site Scripting (XSS)',
              severity,
              confidence,
              message: `AST-Cross-Site Scripting (XSS): ${reason} (${calleeName})`,
              recommendation: 'Use element.textContent or element.setAttribute instead of direct HTML injection. If inserting raw HTML is required, pass variables through DOMPurify.sanitize().',
              cweId: 'CWE-79',
              owaspCategory: 'A03:2021 - Injection',
              node: path.node,
              codeLines,
              sink: calleeName,
              reason
            }));
          }
        }
      },
      
      // 2. Assigning to innerHTML or outerHTML
      AssignmentExpression(path) {
        const { left, right } = path.node;
        if (left.type === 'MemberExpression') {
          const propName = left.property.type === 'Identifier' ? left.property.name : '';
          
          if (propName === 'innerHTML' || propName === 'outerHTML') {
            // Skip if static literal
            if (isStaticLiteral(right)) {
              return;
            }

            if (isDynamic(right)) {
              const userControlled = isUserControlled(right);
              const sanitized = isSanitized(right);

              // Skip if sanitized
              if (sanitized) {
                return;
              }

              let confidence = 0.6; // Medium
              let severity = 'High';
              let reason = `Dynamic value assigned to left-side ${propName}`;

              if (userControlled) {
                confidence = 1.0; // High
                severity = 'High';
                reason = `Dynamic user-controlled input assigned directly to ${propName} without sanitization`;
              }

              findings.push(buildFinding({
                id: 'JS-XSS-102',
                type: 'Cross-Site Scripting (XSS)',
                severity,
                confidence,
                message: `AST-Cross-Site Scripting (XSS): ${reason}`,
                recommendation: 'Avoid assigning dynamic code directly to innerHTML. Use textContent to ensure raw strings are treated as plain text, or sanitize beforehand.',
                cweId: 'CWE-79',
                owaspCategory: 'A03:2021 - Injection',
                node: path.node,
                codeLines,
                sink: propName,
                reason
              }));
            }
          }
        }
      },
      
      // 3. React JSX Attributes (dangerouslySetInnerHTML)
      JSXAttribute(path) {
        if (path.node.name.name === 'dangerouslySetInnerHTML') {
          const value = path.node.value;
          
          // Let's check if the inner HTML is dynamic, user-controlled or sanitized.
          // React format: dangerouslySetInnerHTML={{ __html: dynamicValue }}
          let isStatic = false;
          let userControlled = false;
          let sanitized = false;
          let nodeToInspect = value;

          if (value && value.type === 'JSXExpressionContainer' && value.expression.type === 'ObjectExpression') {
            const htmlProp = value.expression.properties.find(p => p.type === 'ObjectProperty' && (p.key.name === '__html' || p.key.value === '__html'));
            if (htmlProp) {
              nodeToInspect = htmlProp.value;
              isStatic = isStaticLiteral(htmlProp.value);
              userControlled = isUserControlled(htmlProp.value);
              sanitized = isSanitized(htmlProp.value);
            }
          }

          if (isStatic) {
            return; // Skip if static
          }

          // Skip if sanitized
          if (sanitized) {
            return;
          }

          let confidence = 0.6; // Medium
          let severity = 'High';
          let reason = 'React dangerouslySetInnerHTML attribute detected with dynamic content';

          if (userControlled) {
            confidence = 1.0;
            severity = 'High';
            reason = 'React dangerouslySetInnerHTML attribute loaded with dynamic user-controlled input';
          }

          findings.push(buildFinding({
            id: 'JS-XSS-103',
            type: 'Cross-Site Scripting (XSS)',
            severity,
            confidence,
            message: `AST-Cross-Site Scripting (XSS): ${reason}`,
            recommendation: 'Avoid dangerouslySetInnerHTML where possible. If mandatory, pass the content through DOMPurify.sanitize() to strip out executable JavaScript scripts.',
            cweId: 'CWE-79',
            owaspCategory: 'A03:2021 - Injection',
            node: path.node,
            codeLines,
            sink: 'dangerouslySetInnerHTML',
            reason
          }));
        }
      }
    };
  }
};
