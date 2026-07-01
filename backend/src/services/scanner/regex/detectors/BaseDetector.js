const patterns = require('../patterns');
const { calculateCVSS } = require('../../utils/severity');

/**
 * Base Detector Class
 * Provides shared capabilities for pattern matching, snippet extraction,
 * false-positive filtering, and result formatting.
 */
class BaseDetector {
  /**
   * @param {string} name - Name of vulnerability class (e.g. 'SQL Injection')
   * @param {string} type - Vulnerability type code (e.g. 'sqli')
   * @param {string} patternKey - Key inside patterns.js (e.g. 'sqlInjection')
   */
  constructor(name, type, patternKey) {
    this.name = name;
    this.type = type;
    this.patternKey = patternKey;
  }

  /**
   * Detect vulnerabilities in source code
   * @param {string} code - Source code
   * @param {string} language - Target language
   * @returns {Array} List of findings
   */
  detect(code, language) {
    const findings = [];
    const categoryRules = patterns[this.patternKey] || {};
    
    // Get language-specific rules and global rules
    const languagePatterns = categoryRules[language] || [];
    const allPatterns = categoryRules.all || [];
    const patternsToCheck = [...languagePatterns, ...allPatterns];

    if (patternsToCheck.length === 0) {
      return findings;
    }

    const lines = code.split('\n');

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      
      // Skip comments or unwanted lines if hook is implemented
      if (this.shouldSkipLine && this.shouldSkipLine(line, language)) {
        return;
      }

      patternsToCheck.forEach((rule) => {
        // Ensure global regex is reset
        rule.regex.lastIndex = 0;
        
        const matches = line.matchAll(rule.regex);
        
        for (const match of matches) {
          // Check for false positive filter hooks
          if (this.isFalsePositive && this.isFalsePositive(match[0], line, language)) {
            continue;
          }

          // Extract code snippet context
          const snippet = this.extractSnippet(lines, index);
          
          // Calculate confidence
          const confidence = this.calculateConfidence 
            ? this.calculateConfidence(line, match[0], language, rule)
            : (rule.confidence || 80);

          // Calculate CVSS score
          const cvssScore = calculateCVSS(rule.severity, confidence);

          findings.push({
            id: rule.id, // e.g. PY-CMD-001
            type: this.name,
            severity: rule.severity,
            cvssScore: cvssScore,
            line: lineNumber,
            column: match.index !== undefined ? match.index : 0,
            snippet: snippet,
            message: rule.message,
            recommendation: rule.recommendation || '',
            pattern: rule.regex.source,
            confidence: confidence,
            cweId: rule.cweId,
            owaspCategory: rule.owaspCategory,
            source: 'regex',
          });
        }
      });
    });

    return this.deduplicateFindings(findings);
  }

  /**
   * Extract code snippet context (line + 2 lines context before and after)
   * @param {Array} lines - Source code split by lines
   * @param {number} lineIndex - Vulnerable line index (0-based)
   * @returns {string} Code snippet
   */
  extractSnippet(lines, lineIndex) {
    const contextLines = 2;
    const startLine = Math.max(0, lineIndex - contextLines);
    const endLine = Math.min(lines.length - 1, lineIndex + contextLines);
    
    const snippetLines = [];
    for (let i = startLine; i <= endLine; i++) {
      const prefix = i === lineIndex ? '> ' : '  ';
      snippetLines.push(`${prefix}${i + 1} | ${lines[i]}`);
    }
    
    return snippetLines.join('\n');
  }

  /**
   * Deduplicate findings on the same line with same ID/type
   * @param {Array} findings - Findings array
   * @returns {Array} Deduplicated findings
   */
  deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter(finding => {
      const key = `${finding.line}-${finding.id || finding.type}-${finding.message}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  /**
   * Helper to check if a line is a comment in the target language
   */
  isCommentLine(line, language) {
    const trimmed = line.trim();
    const commentPrefixes = {
      javascript: ['//', '/*', '*'],
      typescript: ['//', '/*', '*'],
      java: ['//', '/*', '*'],
      csharp: ['//', '/*', '*'],
      go: ['//', '/*', '*'],
      php: ['//', '#', '/*'],
      python: ['#'],
      ruby: ['#'],
    };

    const prefixes = commentPrefixes[language] || ['//', '#'];
    return prefixes.some(prefix => trimmed.startsWith(prefix));
  }
}

module.exports = BaseDetector;
