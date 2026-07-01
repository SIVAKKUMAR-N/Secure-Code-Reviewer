/**
 * Scanner Engine Orchestrator
 * Coordinates the hybrid AST structural analysis and Regex heuristic scanning.
 * 
 * Architecture:
 * 1. Receives code and programming language.
 * 2. If the language is JavaScript or TypeScript:
 *    a. Parses source code into AST using Babel.
 *    b. Runs 6 AST visitors (SQLi, Command Injection, eval, XSS, SSRF, Path Traversal).
 *    c. Runs 14 Regex detectors (Secrets, weak configs, and fallback checks).
 *    d. Merges and deduplicates findings, keeping AST findings over Regex on the same line.
 * 3. If the language is Python, Java, PHP, C#, Ruby, or Go:
 *    a. Falls back entirely to the Regex pattern scanner (scanning all 14 categories).
 * 4. Aggregates, calculates CVSS & risk scores, and returns a unified scan report.
 */

const parser = require('./ast/parser');
const { runTraversal } = require('./ast/traversal');
const RegexScanner = require('./regex/regexScanner');
const { mergeFindings } = require('./utils/merger');
const { calculateRiskScore } = require('./utils/severity');
const logger = require('../../utils/logger');

class ScannerEngine {
  constructor() {
    this.regexScanner = new RegexScanner();
    logger.info('Scanner Engine initialized with Hybrid AST + Regex SAST support');
  }

  /**
   * Scan code for vulnerabilities
   * @param {string} code - Source code to analyze
   * @param {string} language - Programming language (e.g., javascript, python)
   * @returns {Object} Scan results with vulnerabilities and metadata
   */
  async scan(code, language) {
    const startTime = Date.now();
    
    try {
      if (!code || typeof code !== 'string') {
        throw new Error('Invalid code input');
      }

      if (!language || typeof language !== 'string') {
        throw new Error('Invalid language input');
      }

      const normalizedLanguage = language.toLowerCase().trim();
      logger.info(`Starting hybrid scan for ${normalizedLanguage} code (${code.length} characters)`);

      let astFindings = [];
      let regexFindings = [];

      const isAstSupported = ['javascript', 'typescript'].includes(normalizedLanguage);

      // 1. AST Analysis (only for JavaScript / TypeScript)
      if (isAstSupported) {
        try {
          logger.info(`Parsing AST for ${normalizedLanguage}...`);
          const ext = normalizedLanguage === 'typescript' ? 'ts' : 'js';
          const ast = parser.parse(code, `code.${ext}`);
          
          logger.info('Running AST Traversal and structural detectors...');
          astFindings = runTraversal(ast, code);
          logger.info(`AST analysis complete. Found ${astFindings.length} issue(s)`);
        } catch (astError) {
          logger.error(`AST analysis failed: ${astError.message}. Falling back to full Regex scanning.`);
          // If AST parsing fails (due to syntax errors), we continue with Regex fallback
        }
      }

      // 2. Regex Analysis
      logger.info(`Running Regex heuristic scanner for ${normalizedLanguage}...`);
      regexFindings = await this.regexScanner.scan(code, normalizedLanguage);
      logger.info(`Regex scan complete. Found ${regexFindings.length} issue(s)`);

      // 3. Merge + Deduplicate findings
      let finalFindings = [];
      if (isAstSupported && astFindings.length > 0) {
        finalFindings = mergeFindings(astFindings, regexFindings);
      } else {
        finalFindings = regexFindings;
      }

      // 4. Sort findings by severity and line number
      const sortedFindings = this._sortFindings(finalFindings);

      // 5. Calculate statistics and overall risk score
      const scanDuration = Date.now() - startTime;
      const statistics = this._calculateStatistics(sortedFindings);

      logger.info(`Hybrid scan completed in ${scanDuration}ms. Found ${sortedFindings.length} total vulnerabilities`);

      return {
        vulnerabilities: sortedFindings,
        statistics,
        scanDuration,
        language: normalizedLanguage,
        timestamp: new Date().toISOString(),
      };

    } catch (error) {
      logger.error(`Scanner Engine error: ${error.message}`);
      throw error;
    }
  }

  /**
   * Sort findings by severity and line number
   * @param {Array} findings - All vulnerability findings
   * @returns {Array} Sorted findings
   */
  _sortFindings(findings) {
    const severityOrder = {
      'Critical': 0,
      'High': 1,
      'Medium': 2,
      'Low': 3,
      'Info': 4,
    };

    return findings.sort((a, b) => {
      // First sort by severity
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;

      // Then sort by line number
      return a.line - b.line;
    });
  }

  /**
   * Calculate scan statistics
   * @param {Array} findings - All vulnerability findings
   * @returns {Object} Statistics object
   */
  _calculateStatistics(findings) {
    const stats = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      byType: {},
      riskScore: 0,
    };

    findings.forEach(finding => {
      const severity = finding.severity.toLowerCase();
      stats[severity] = (stats[severity] || 0) + 1;

      const type = finding.type;
      stats.byType[type] = (stats.byType[type] || 0) + 1;
    });

    stats.riskScore = calculateRiskScore(findings);

    return stats;
  }

  /**
   * Calculate overall risk score based on vulnerabilities found
   * @param {Array} findings - Findings array
   * @returns {number} Risk score (0-100)
   */
  _calculateRiskScore(findings) {
    return calculateRiskScore(findings);
  }

  /**
   * Get list of available detectors (for API compatibility)
   * @returns {Array} List of detectors
   */
  getDetectors() {
    return this.regexScanner.detectors.map(detector => ({
      name: detector.name,
      type: detector.type,
    }));
  }

  /**
   * Get supported languages
   * @returns {Array} List of supported languages
   */
  getSupportedLanguages() {
    return [
      'javascript',
      'typescript',
      'python',
      'java',
      'php',
      'csharp',
      'ruby',
      'go',
    ];
  }
}

module.exports = ScannerEngine;