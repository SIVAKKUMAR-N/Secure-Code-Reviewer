const { getCalleeName, isDynamic, isStaticLiteral, isUserControlled, isSanitized } = require('../utils/nodeHelpers');
const { buildFinding } = require('../utils/findingBuilder');

/**
 * SQL Injection AST Detector
 * Checks for query/execute database calls passed dynamic SQL strings.
 */
module.exports = {
  visitor(findings, codeLines) {
    return {
      CallExpression(path) {
        const calleeName = getCalleeName(path.node.callee);
        const sqlSinks = ['query', 'execute', 'raw', 'where', 'find', 'findOne', 'findAll'];
        
        const isSink = sqlSinks.some(sink => 
          calleeName === sink || calleeName.endsWith(`.${sink}`)
        );

        if (isSink && path.node.arguments.length > 0) {
          const firstArg = path.node.arguments[0];

          // 1. Static Literal check - skip if fully static
          if (isStaticLiteral(firstArg)) {
            return;
          }

          // 2. Parameterization check
          let isParameterized = false;
          if (path.node.arguments.length > 1) {
            const secondArg = path.node.arguments[1];
            
            // Check for array parameter list, object with replacements/bind, or variables representing them
            if (secondArg.type === 'ArrayExpression') {
              isParameterized = true;
            } else if (secondArg.type === 'ObjectExpression') {
              isParameterized = secondArg.properties.some(prop => {
                if (prop.type === 'ObjectProperty') {
                  const keyName = prop.key.type === 'Identifier' ? prop.key.name : (prop.key.type === 'StringLiteral' ? prop.key.value : '');
                  return ['replacements', 'bind', 'values', 'params', 'parameters'].includes(keyName);
                }
                return false;
              });
            } else if (secondArg.type === 'Identifier') {
              isParameterized = true; // Assume identifier is a params array or options object
            }
          }

          // Also check if the string contains placeholders if it is inspectable
          const hasPlaceholder = (node) => {
            if (!node) return false;
            if (node.type === 'StringLiteral' || node.type === 'Literal') {
              const val = String(node.value || '');
              return val.includes('?') || /\$\d+/.test(val) || /:\w+/.test(val);
            }
            if (node.type === 'TemplateLiteral') {
              return node.quasis.some(q => {
                const val = q.value.raw || '';
                return val.includes('?') || /\$\d+/.test(val) || /:\w+/.test(val);
              });
            }
            if (node.type === 'BinaryExpression') {
              return hasPlaceholder(node.left) || hasPlaceholder(node.right);
            }
            return false;
          };

          if (isParameterized || (path.node.arguments.length > 1 && hasPlaceholder(firstArg))) {
            return; // Skip parameterized queries
          }

          if (isDynamic(firstArg)) {
            const userControlled = isUserControlled(firstArg);
            const sanitized = isSanitized(firstArg);

            let confidence = 0.6; // Medium
            let severity = 'High';
            let reason = 'Dynamic SQL query construction passed to database sink';

            if (userControlled && !sanitized) {
              confidence = 1.0; // High
              severity = 'Critical';
              reason = 'Dynamic user-controlled input passed directly to database SQL query sink';
            } else if (sanitized) {
              confidence = 0.2; // Low
              severity = 'Medium';
              reason = 'Dynamic SQL query containing sanitized/validated input passed to database sink';
            }

            findings.push(buildFinding({
              id: 'JS-SQLI-101',
              type: 'SQL Injection',
              severity,
              confidence,
              message: `AST-SQL Injection: ${reason} (${calleeName})`,
              recommendation: 'Use parameterized queries or ORM query builders (e.g. db.query("SELECT * FROM users WHERE id = ?", [id])) instead of building queries via string concatenation.',
              cweId: 'CWE-89',
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
