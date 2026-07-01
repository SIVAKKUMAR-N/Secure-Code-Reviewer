/**
 * Findings Merger & Deduplicator
 * Merges findings from structural AST analysis and pattern-based Regex scanning.
 * 
 * Educational Context:
 * - Hybrid analysis gives us both structural precision (AST) and signature coverage (Regex).
 * - For overlapping categories (e.g., SQL Injection, XSS, Command Injection) on JavaScript/TypeScript:
 *   - AST is far more precise because it checks structure and arguments.
 *   - If both AST and Regex find an issue of the same category on the same line, we discard 
 *     the Regex finding to prevent double-counting on the reports/dashboard, keeping the 
 *     structurally validated AST finding.
 */

/**
 * Merges findings from AST and Regex, deduplicating overlaps on JS/TS.
 * @param {Array} astFindings - Findings returned from AST visitor traversal
 * @param {Array} regexFindings - Findings returned from Regex pattern matching
 * @returns {Array} Consolidated list of findings
 */
function mergeFindings(astFindings, regexFindings) {
  const allFindings = [...astFindings, ...regexFindings];
  const kept = [];
  
  // Group findings by line number
  const lineGroups = {};
  allFindings.forEach(f => {
    const line = f.line;
    if (!lineGroups[line]) {
      lineGroups[line] = [];
    }
    lineGroups[line].push(f);
  });
  
  // Apply priority-based deduplication on each line
  Object.keys(lineGroups).forEach(lineStr => {
    const lineFindings = lineGroups[lineStr];
    
    // Check if there is a Critical or High AST finding on this line
    const hasCriticalOrHighAST = lineFindings.some(f => 
      f.source === 'ast' && (f.severity === 'Critical' || f.severity === 'High')
    );
    
    // Check if there is any specific (non-generic) Regex finding on this line
    const hasRegexSpecific = lineFindings.some(f => 
      f.source !== 'ast' && !['Missing Input Validation', 'Weak Validation', 'Generic Dynamic Usage'].includes(f.type)
    );
    
    // Track AST types on this line to suppress overlapping Regex findings of the same type
    const astTypesOnLine = new Set();
    lineFindings.forEach(f => {
      if (f.source === 'ast') {
        astTypesOnLine.add(f.type);
      }
    });
    
    lineFindings.forEach(f => {
      const isGeneric = ['Missing Input Validation', 'Weak Validation', 'Generic Dynamic Usage'].includes(f.type);
      
      // 1. Priority suppression for generic findings
      if (isGeneric && (hasCriticalOrHighAST || hasRegexSpecific)) {
        return; // Suppress lower-priority generic finding
      }
      
      // 2. Suppress Regex finding if there is a structurally validated AST finding of the same type
      if (f.source !== 'ast' && astTypesOnLine.has(f.type)) {
        return; // Suppress overlapping regex finding
      }
      
      kept.push(f);
    });
  });

  return kept;
}

module.exports = { mergeFindings };
