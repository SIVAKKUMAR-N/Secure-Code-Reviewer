const { calculateCVSS } = require('../../utils/severity');

/**
 * Standardized AST Finding Builder
 * Converts an AST node match and rule metadata into a standard SAST finding structure.
 * 
 * @param {Object} params - Builder inputs
 * @param {string} params.id - Finding ID (e.g. JS-SQLI-101)
 * @param {string} params.type - Category type (e.g. SQL Injection)
 * @param {string} params.severity - Qualitative severity (Critical, High, Medium, Low)
 * @param {number} params.confidence - Confidence level (0-100)
 * @param {string} params.message - Description of findings
 * @param {string} params.recommendation - How to remediate
 * @param {string} params.cweId - CWE classification
 * @param {string} params.owaspCategory - OWASP Top 10 mapping
 * @param {Object} params.node - The matching AST node
 * @param {Array<string>} params.codeLines - Split lines of the source file
 * @returns {Object} Standardized finding object
 */
function buildFinding({
  id,
  type,
  severity,
  confidence, // range 0.0 -> 1.0
  message,
  recommendation,
  cweId,
  owaspCategory,
  node,
  codeLines,
  sink = '',
  reason = ''
}) {
  const line = node.loc ? node.loc.start.line : 1;
  const column = node.loc ? node.loc.start.column : 0;
  const lineIndex = line - 1;

  // Extract a 5-line snippet context (matching BaseDetector extraction style)
  const contextLines = 2;
  const startLine = Math.max(0, lineIndex - contextLines);
  const endLine = Math.min(codeLines.length - 1, lineIndex + contextLines);
  
  const snippetLines = [];
  for (let i = startLine; i <= endLine; i++) {
    const prefix = i === lineIndex ? '> ' : '  ';
    snippetLines.push(`${prefix}${i + 1} | ${codeLines[i]}`);
  }
  const snippet = snippetLines.join('\n');

  // Scale decimal confidence (0.0 - 1.0) to 0 - 100 for calculateCVSS
  const scaledConfidence = confidence <= 1.0 ? Math.round(confidence * 100) : confidence;
  const cvssScore = calculateCVSS(severity, scaledConfidence);

  return {
    id,
    type,
    severity,
    cvssScore,
    line,
    column,
    snippet,
    message,
    recommendation,
    confidence: confidence <= 1.0 ? confidence : parseFloat((confidence / 100).toFixed(2)),
    cweId,
    owaspCategory,
    source: 'ast', // Explicit identifier for AST-sourced findings
    sink,
    reason
  };
}

module.exports = { buildFinding };
