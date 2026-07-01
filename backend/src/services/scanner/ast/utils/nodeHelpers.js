/**
 * AST Node Helpers
 * Utilities for analyzing AST node types and resolving expression structures.
 * 
 * Educational Context:
 * - AST nodes are strongly typed objects representing code semantics.
 * - By checking the specific type of a node, we can determine how it evaluates:
 *   - A StringLiteral represents a static, safe hardcoded string (usually low risk).
 *   - BinaryExpression (e.g. `a + b`) or TemplateLiteral (e.g. `` `a ${b}` ``) indicate 
 *     that data is being combined dynamically, representing high injection risk if fed into sinks.
 *   - Identifier (e.g. `userInput`) represents a variable reference, which could contain untrusted data.
 */

/**
 * Checks if an AST node represents dynamic variable usage or string construction.
 * Nodes that qualify:
 * - BinaryExpression (e.g. "str" + variable)
 * - TemplateLiteral with one or more dynamic interpolations (e.g. `str ${val}`)
 * - Identifier (e.g. userInput variable)
 * - CallExpression (e.g. getHost())
 * - MemberExpression (e.g. req.body.username)
 * 
 * @param {Object} node - AST node to check
 * @returns {boolean} True if the node value is dynamic
 */
function isStaticLiteral(node) {
  if (!node) return false;

  // Primitive literal types in Babel/ESTree
  if (
    node.type === 'StringLiteral' ||
    node.type === 'NumericLiteral' ||
    node.type === 'BooleanLiteral' ||
    node.type === 'NullLiteral' ||
    node.type === 'RegExpLiteral' ||
    node.type === 'BigIntLiteral'
  ) {
    return true;
  }

  // Generic Literal node fallback
  if (node.type === 'Literal') {
    return true;
  }

  // TemplateLiteral with no expressions (e.g. `hello`)
  if (node.type === 'TemplateLiteral') {
    return !node.expressions || node.expressions.length === 0;
  }

  // BinaryExpression where both sides are static (e.g. "a" + "b")
  if (node.type === 'BinaryExpression') {
    return isStaticLiteral(node.left) && isStaticLiteral(node.right);
  }

  // LogicalExpression where both sides are static (e.g. "a" || "b")
  if (node.type === 'LogicalExpression') {
    return isStaticLiteral(node.left) && isStaticLiteral(node.right);
  }

  // ConditionalExpression where all paths are static (e.g. true ? "a" : "b")
  if (node.type === 'ConditionalExpression') {
    return (
      isStaticLiteral(node.test) &&
      isStaticLiteral(node.consequent) &&
      isStaticLiteral(node.alternate)
    );
  }

  // ArrayExpression where all elements are static (e.g. [1, 2, "three"])
  if (node.type === 'ArrayExpression') {
    return node.elements.every(el => el === null || isStaticLiteral(el));
  }

  // ObjectExpression where all properties are static
  if (node.type === 'ObjectExpression') {
    return node.properties.every(prop => {
      if (prop.type === 'ObjectProperty') {
        const keyStatic = !prop.computed || isStaticLiteral(prop.key);
        return keyStatic && isStaticLiteral(prop.value);
      }
      return false; // SpreadElement etc. are treated as dynamic
    });
  }

  return false;
}

function isDynamic(node) {
  if (!node) return false;

  // 1. Literal types are static, hence NOT dynamic
  if (isStaticLiteral(node)) {
    return false;
  }

  // 2. Identifier is dynamic
  if (node.type === 'Identifier') {
    return true;
  }

  // 3. CallExpression is dynamic
  if (node.type === 'CallExpression') {
    return true;
  }

  // 4. MemberExpression is dynamic
  if (node.type === 'MemberExpression') {
    return true;
  }

  // 5. BinaryExpression is dynamic if either side is dynamic
  if (node.type === 'BinaryExpression') {
    return isDynamic(node.left) || isDynamic(node.right);
  }

  // 6. TemplateLiteral is dynamic if it contains dynamic expressions
  if (node.type === 'TemplateLiteral') {
    return node.expressions && node.expressions.some(expr => isDynamic(expr));
  }

  // 7. ConditionalExpression is dynamic if any branch/test is dynamic
  if (node.type === 'ConditionalExpression') {
    return isDynamic(node.test) || isDynamic(node.consequent) || isDynamic(node.alternate);
  }

  // 8. LogicalExpression is dynamic if either side is dynamic
  if (node.type === 'LogicalExpression') {
    return isDynamic(node.left) || isDynamic(node.right);
  }

  // 9. ArrayExpression is dynamic if any element is dynamic
  if (node.type === 'ArrayExpression') {
    return node.elements.some(el => el && isDynamic(el));
  }

  // 10. ObjectExpression is dynamic if any property value or computed key is dynamic
  if (node.type === 'ObjectExpression') {
    return node.properties.some(prop => {
      if (prop.type === 'ObjectProperty') {
        return isDynamic(prop.value) || (prop.computed && isDynamic(prop.key));
      }
      return true; // SpreadElement etc.
    });
  }

  // 11. AssignmentExpression is dynamic if right side is dynamic
  if (node.type === 'AssignmentExpression') {
    return isDynamic(node.right);
  }

  return true;
}

function getMemberExpressionStr(node) {
  if (!node) return '';
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'MemberExpression') {
    const objStr = getMemberExpressionStr(node.object);
    let propStr = '';
    if (node.property.type === 'Identifier') {
      propStr = node.property.name;
    } else if (node.property.type === 'StringLiteral') {
      propStr = node.property.value;
    }
    if (objStr && propStr) {
      return `${objStr}.${propStr}`;
    }
    return objStr || propStr || '';
  }
  return '';
}

function isUserControlled(node) {
  if (!node) return false;

  // MemberExpression checking
  if (node.type === 'MemberExpression') {
    const str = getMemberExpressionStr(node);
    const sources = [
      'req.body', 'req.query', 'req.params',
      'request.args', 'request.form',
      'process.argv', 'window.location',
      'document.cookie', 'localStorage'
    ];
    if (sources.some(source => str === source || str.startsWith(source + '.'))) {
      return true;
    }
  }

  // Direct Identifier references
  if (node.type === 'Identifier') {
    const name = node.name;
    return ['localStorage', 'window.location', 'document.cookie'].includes(name);
  }

  // CallExpression checking
  if (node.type === 'CallExpression') {
    const calleeName = getCalleeName(node.callee);
    
    // e.g. localStorage.getItem(...)
    if (calleeName && (calleeName === 'localStorage.getItem' || (calleeName.endsWith('.getItem') && calleeName.includes('localStorage')))) {
      return true;
    }
    
    // e.g. urlParams.get(...) or URLSearchParams.get
    if (calleeName && calleeName.endsWith('.get') && (calleeName.includes('params') || calleeName.includes('Params') || calleeName.includes('searchParams'))) {
      return true;
    }
    
    // Check if arguments contain user-controlled input
    if (node.arguments && node.arguments.some(arg => isUserControlled(arg))) {
      return true;
    }
  }

  // NewExpression checking
  if (node.type === 'NewExpression') {
    const calleeName = getCalleeName(node.callee) || (node.callee.type === 'Identifier' ? node.callee.name : '');
    if (calleeName === 'URLSearchParams') {
      return true;
    }
    if (node.arguments && node.arguments.some(arg => isUserControlled(arg))) {
      return true;
    }
  }

  // BinaryExpression
  if (node.type === 'BinaryExpression') {
    return isUserControlled(node.left) || isUserControlled(node.right);
  }

  // TemplateLiteral
  if (node.type === 'TemplateLiteral') {
    return node.expressions && node.expressions.some(expr => isUserControlled(expr));
  }

  // ConditionalExpression
  if (node.type === 'ConditionalExpression') {
    return isUserControlled(node.consequent) || isUserControlled(node.alternate);
  }

  // LogicalExpression
  if (node.type === 'LogicalExpression') {
    return isUserControlled(node.left) || isUserControlled(node.right);
  }

  // AssignmentExpression
  if (node.type === 'AssignmentExpression') {
    return isUserControlled(node.right);
  }

  // ArrayExpression
  if (node.type === 'ArrayExpression') {
    return node.elements.some(el => el && isUserControlled(el));
  }

  // ObjectExpression
  if (node.type === 'ObjectExpression') {
    return node.properties.some(prop => prop.type === 'ObjectProperty' && isUserControlled(prop.value));
  }

  return false;
}

function isSanitized(node) {
  if (!node) return false;

  // Static literals are safe and inherently sanitized
  if (isStaticLiteral(node)) {
    return true;
  }

  if (node.type === 'CallExpression') {
    const calleeName = getCalleeName(node.callee);
    
    const sanitizers = [
      'validator.escape',
      'DOMPurify.sanitize',
      'encodeURIComponent',
      'parseInt',
      'sanitizeHtml',
      'sanitizeHTML',
      'validationResult',
      'escape',
      'path.basename',
      'basename'
    ];

    if (calleeName) {
      if (sanitizers.includes(calleeName) || sanitizers.some(s => calleeName.endsWith(`.${s}`))) {
        return true;
      }
      if (calleeName.endsWith('.validate') || calleeName.startsWith('Joi')) {
        return true;
      }
      if (calleeName.endsWith('.parse') || calleeName.endsWith('.safeParse')) {
        return true;
      }
      if (['check', 'body', 'param', 'query', 'validationResult'].includes(calleeName)) {
        return true;
      }
    }
  }

  // BinaryExpression is sanitized if both sides are sanitized or static
  if (node.type === 'BinaryExpression') {
    return isSanitized(node.left) && isSanitized(node.right);
  }

  // TemplateLiteral is sanitized if all components are sanitized or static
  if (node.type === 'TemplateLiteral') {
    return !node.expressions || node.expressions.every(expr => isSanitized(expr));
  }

  // ConditionalExpression
  if (node.type === 'ConditionalExpression') {
    return isSanitized(node.consequent) && isSanitized(node.alternate);
  }

  // LogicalExpression
  if (node.type === 'LogicalExpression') {
    return isSanitized(node.left) && isSanitized(node.right);
  }

  // AssignmentExpression
  if (node.type === 'AssignmentExpression') {
    return isSanitized(node.right);
  }

  return false;
}

function isBinaryOrTemplate(node) {
  if (!node) return false;
  
  if (node.type === 'BinaryExpression') {
    return true;
  }
  
  if (node.type === 'TemplateLiteral') {
    return node.expressions && node.expressions.length > 0;
  }
  
  return false;
}

function getCalleeName(node) {
  if (!node) return '';

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'MemberExpression') {
    const objName = getCalleeName(node.object);
    let propName = '';
    
    if (node.property.type === 'Identifier') {
      propName = node.property.name;
    }
    
    if (objName && propName) {
      return `${objName}.${propName}`;
    }
    return propName || objName || '';
  }

  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require') {
    return 'require';
  }

  return '';
}

module.exports = {
  isDynamic,
  isStaticLiteral,
  isUserControlled,
  isSanitized,
  isBinaryOrTemplate,
  getCalleeName
};
