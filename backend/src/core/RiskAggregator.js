/**
 * RiskAggregator
 * Computes summary metrics, risk scores, OWASP mappings, and CWE breakdowns.
 */
class RiskAggregator {
  /**
   * Aggregates findings and returns summary metrics & mappings
   * @param {Array<Object>} findings - Normalized findings list
   * @param {number} scanDurationMs - Scan execution time in milliseconds
   * @param {number} filesScannedCount - Number of files analyzed
   * @param {number} [parserErrorsCount=0] - Number of files with parser errors
   * @param {Object} [languageCounts={}] - Map of language names to scanned file counts { JavaScript: 421, TypeScript: 183 }
   * @returns {Object} { summary, owaspMapping, cweMapping, riskScore, riskLevel }
   */
  static aggregate(findings = [], scanDurationMs = 0, filesScannedCount = 1, parserErrorsCount = 0, languageCounts = {}) {
    const summary = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      scannedFiles: filesScannedCount,
      parserErrors: parserErrorsCount,
      languageCounts: Object.keys(languageCounts).length > 0 ? languageCounts : { JavaScript: filesScannedCount },
      scanDurationMs
    };

    const owaspMapping = {};
    const cweMapping = {};

    findings.forEach(finding => {
      // 1. Severity counts
      const sev = (finding.severity || 'Medium').toLowerCase();
      if (summary[sev] !== undefined) {
        summary[sev]++;
      }

      // 2. OWASP mapping
      const owasp = finding.owaspCategory || 'Uncategorized';
      if (!owaspMapping[owasp]) {
        owaspMapping[owasp] = [];
      }
      owaspMapping[owasp].push(finding.id);

      // 3. CWE mapping
      const cwe = finding.cweId || 'CWE-20';
      if (!cweMapping[cwe]) {
        cweMapping[cwe] = [];
      }
      cweMapping[cwe].push(finding.id);
    });

    // 4. Calculate Risk Score (0 - 100)
    const riskScore = RiskAggregator.calculateRiskScore(summary);
    const riskLevel = RiskAggregator.getRiskLevel(riskScore);

    summary.riskScore = riskScore;
    summary.riskLevel = riskLevel;

    return {
      summary,
      owaspMapping,
      cweMapping,
      riskScore,
      riskLevel
    };
  }

  /**
   * Calculates a balanced risk score (0-100) based on severity distribution, finding density, and file count.
   */
  static calculateRiskScore(summary) {
    if (!summary || summary.total === 0) return 0;

    const files = Math.max(1, summary.scannedFiles || 1);

    // Base severity weights
    const rawPoints = (
      summary.critical * 40 +
      summary.high * 15 +
      summary.medium * 5 +
      summary.low * 1 +
      summary.info * 0.2
    );

    // Finding density factor per file
    const density = summary.total / files;
    const densityMultiplier = Math.min(2.0, Math.max(0.5, Math.sqrt(density)));

    let score = rawPoints * densityMultiplier;

    // Minimum severity floors for calibrated enterprise reporting
    if (summary.critical >= 10) {
      score = Math.max(score, 90 + Math.min(10, summary.critical - 10));
    } else if (summary.critical > 0) {
      score = Math.max(score, 70 + (summary.critical - 1) * 5);
    } else if (summary.high >= 15) {
      score = Math.max(score, 60 + Math.min(20, summary.high - 15));
    } else if (summary.high >= 5) {
      score = Math.max(score, 35 + (summary.high - 5) * 2.5);
    } else if (summary.high > 0) {
      score = Math.max(score, 15 + summary.high * 4);
    } else if (summary.medium > 0) {
      score = Math.max(score, Math.min(20, summary.medium * 5));
    }

    return Math.min(100, Math.round(score));
  }

  static getRiskLevel(riskScore) {
    if (riskScore >= 80) return 'CRITICAL';
    if (riskScore >= 50) return 'HIGH';
    if (riskScore >= 20) return 'MEDIUM';
    if (riskScore > 0) return 'LOW';
    return 'MINIMAL';
  }
}

module.exports = RiskAggregator;
